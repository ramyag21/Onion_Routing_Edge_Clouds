"""
Core agent definitions for the onion routing simulation system.

This module defines the different types of agents that participate in the
onion routing network: Entry nodes, Relay nodes, Exit nodes, and API Gateway agents.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import uuid
from datetime import datetime

from cryptography.fernet import Fernet
import numpy as np


class AgentType(Enum):
    """Types of agents in the onion routing network."""
    ENTRY_NODE = "entry_node"
    RELAY_NODE = "relay_node"
    EXIT_NODE = "exit_node"
    API_GATEWAY = "api_gateway"
    CLIENT = "client"


@dataclass
class Message:
    """Represents a message in the onion routing network."""
    id: str
    payload: bytes
    headers: Dict[str, str]
    timestamp: datetime
    source_agent: Optional[str] = None
    destination_agent: Optional[str] = None
    route_path: Optional[List[str]] = None
    encryption_layers: Optional[List[str]] = None


@dataclass
class TrafficMetrics:
    """Traffic and performance metrics for analysis."""
    request_count: int = 0
    response_time_ms: float = 0.0
    throughput_rps: float = 0.0
    error_count: int = 0
    ddos_detected_count: int = 0
    false_positive_count: int = 0
    false_negative_count: int = 0


class BaseAgent(ABC):
    """Abstract base class for all agents in the onion routing network."""
    
    def __init__(self, agent_id: str, agent_type: AgentType):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.is_active = True
        self.message_queue = asyncio.Queue()
        self.metrics = TrafficMetrics()
        self.logger = logging.getLogger(f"{agent_type.value}_{agent_id}")
        
        # Cryptographic components
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Network connections to other agents
        self.connected_agents: Dict[str, 'BaseAgent'] = {}
        
    @abstractmethod
    async def process_message(self, message: Message) -> Optional[Message]:
        """Process an incoming message and return the next message in the chain."""
        pass
    
    async def send_message(self, message: Message, target_agent_id: str) -> bool:
        """Send a message to another agent."""
        if target_agent_id in self.connected_agents:
            target_agent = self.connected_agents[target_agent_id]
            await target_agent.receive_message(message)
            return True
        return False
    
    async def receive_message(self, message: Message):
        """Receive and queue a message for processing."""
        message.destination_agent = self.agent_id
        await self.message_queue.put(message)
    
    async def start(self):
        """Start the agent's message processing loop."""
        while self.is_active:
            try:
                message = await asyncio.wait_for(self.message_queue.get(), timeout=1.0)
                processed_message = await self.process_message(message)
                
                if processed_message:
                    # Forward to next agent in the route
                    next_agent_id = self._get_next_agent(processed_message)
                    if next_agent_id:
                        await self.send_message(processed_message, next_agent_id)
                        
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")
    
    def connect_to_agent(self, agent: 'BaseAgent'):
        """Establish a connection to another agent."""
        self.connected_agents[agent.agent_id] = agent
        agent.connected_agents[self.agent_id] = self
    
    def _get_next_agent(self, message: Message) -> Optional[str]:
        """Determine the next agent in the routing path."""
        if message.route_path and len(message.route_path) > 0:
            return message.route_path.pop(0)
        return None
    
    def encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload using the agent's key."""
        return self.cipher_suite.encrypt(payload)
    
    def decrypt_payload(self, encrypted_payload: bytes) -> bytes:
        """Decrypt payload using the agent's key."""
        return self.cipher_suite.decrypt(encrypted_payload)


class ClientAgent(BaseAgent):
    """Client agent that initiates requests through the onion routing network."""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.CLIENT)
        self.onion_route_keys: List[bytes] = []
    
    async def create_onion_request(self, original_payload: str, route_path: List[str]) -> Message:
        """Create an onion-encrypted request with multiple layers."""
        # Start with the original payload
        current_payload = original_payload.encode()
        
        # Apply encryption layers in reverse order (innermost first)
        for agent_id in reversed(route_path):
            if agent_id in self.connected_agents:
                agent = self.connected_agents[agent_id]
                current_payload = agent.encrypt_payload(current_payload)
        
        message = Message(
            id=str(uuid.uuid4()),
            payload=current_payload,
            headers={"content-type": "application/json"},
            timestamp=datetime.now(),
            source_agent=self.agent_id,
            route_path=route_path.copy()
        )
        
        return message
    
    async def process_message(self, message: Message) -> Optional[Message]:
        """Process response messages from the network."""
        self.logger.info(f"Received response: {message.id}")
        # For clients, this would typically be the final response
        return None


class EntryNodeAgent(BaseAgent):
    """Entry node agent - first hop in the onion routing network."""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.ENTRY_NODE)
    
    async def process_message(self, message: Message) -> Optional[Message]:
        """Process and decrypt the outermost layer of onion encryption."""
        try:
            # Decrypt one layer
            decrypted_payload = self.decrypt_payload(message.payload)
            
            # Create new message with decrypted payload
            new_message = Message(
                id=message.id,
                payload=decrypted_payload,
                headers=message.headers,
                timestamp=message.timestamp,
                source_agent=message.source_agent,
                route_path=message.route_path
            )
            
            self.metrics.request_count += 1
            self.logger.info(f"Entry node processed message {message.id}")
            
            return new_message
            
        except Exception as e:
            self.logger.error(f"Failed to decrypt message: {e}")
            return None


class RelayNodeAgent(BaseAgent):
    """Relay node agent - intermediate hop in the onion routing network."""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.RELAY_NODE)
        self.ddos_detector = None  # Will be set later
    
    async def process_message(self, message: Message) -> Optional[Message]:
        """Process and decrypt one layer, forward to next node."""
        try:
            # Decrypt one layer
            decrypted_payload = self.decrypt_payload(message.payload)
            
            # Basic DDoS detection (placeholder)
            if await self._detect_ddos_patterns(message):
                self.logger.warning(f"Potential DDoS detected for message {message.id}")
                self.metrics.ddos_detected_count += 1
                return None  # Drop suspicious message
            
            new_message = Message(
                id=message.id,
                payload=decrypted_payload,
                headers=message.headers,
                timestamp=message.timestamp,
                source_agent=message.source_agent,
                route_path=message.route_path
            )
            
            self.metrics.request_count += 1
            self.logger.info(f"Relay node processed message {message.id}")
            
            return new_message
            
        except Exception as e:
            self.logger.error(f"Failed to process message: {e}")
            return None
    
    async def _detect_ddos_patterns(self, message: Message) -> bool:
        """Basic DDoS detection logic (to be enhanced with TinyML)."""
        # Placeholder: Simple rate limiting
        current_time = datetime.now()
        time_window = (current_time - message.timestamp).total_seconds()
        
        # If too many requests in short time window, flag as potential DDoS
        if self.metrics.request_count > 100 and time_window < 10:
            return True
        
        return False


class ExitNodeAgent(BaseAgent):
    """Exit node agent - final decryption before reaching API gateway."""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.EXIT_NODE)
    
    async def process_message(self, message: Message) -> Optional[Message]:
        """Decrypt final layer and prepare for API gateway."""
        try:
            # Decrypt final layer to reveal original payload
            decrypted_payload = self.decrypt_payload(message.payload)
            
            new_message = Message(
                id=message.id,
                payload=decrypted_payload,
                headers=message.headers,
                timestamp=message.timestamp,
                source_agent=message.source_agent,
                route_path=message.route_path
            )
            
            self.metrics.request_count += 1
            self.logger.info(f"Exit node processed message {message.id}")
            
            return new_message
            
        except Exception as e:
            self.logger.error(f"Failed to decrypt final layer: {e}")
            return None


class APIGatewayAgent(BaseAgent):
    """API Gateway agent - handles final request processing and response generation."""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.API_GATEWAY)
        self.backend_services = {}
        self.ddos_detector = None  # TinyML model will be loaded here
    
    async def process_message(self, message: Message) -> Optional[Message]:
        """Process the final decrypted request and generate response."""
        try:
            # Parse the decrypted payload
            payload_str = message.payload.decode()
            request_data = json.loads(payload_str)
            
            # Advanced DDoS detection at gateway level
            if await self._advanced_ddos_detection(message, request_data):
                self.logger.warning(f"DDoS attack detected at gateway for message {message.id}")
                self.metrics.ddos_detected_count += 1
                return self._create_error_response(message, "Request blocked - suspicious activity")
            
            # Process legitimate request
            response_data = await self._process_api_request(request_data)
            
            # Create response message
            response_message = Message(
                id=str(uuid.uuid4()),
                payload=json.dumps(response_data).encode(),
                headers={"content-type": "application/json", "status": "200"},
                timestamp=datetime.now(),
                source_agent=self.agent_id,
                destination_agent=message.source_agent
            )
            
            self.metrics.request_count += 1
            self.logger.info(f"API Gateway processed request {message.id}")
            
            return response_message
            
        except Exception as e:
            self.logger.error(f"Failed to process API request: {e}")
            return self._create_error_response(message, "Internal server error")
    
    async def _advanced_ddos_detection(self, message: Message, request_data: Dict) -> bool:
        """Advanced DDoS detection using TinyML models."""
        # Placeholder for TinyML integration
        # Features would include: request rate, payload size, pattern analysis
        features = self._extract_request_features(message, request_data)
        
        # Mock detection logic (to be replaced with actual TinyML model)
        if features.get('request_rate', 0) > 1000:
            return True
        
        return False
    
    def _extract_request_features(self, message: Message, request_data: Dict) -> Dict:
        """Extract features for DDoS detection."""
        return {
            'request_rate': self.metrics.request_count,
            'payload_size': len(message.payload),
            'timestamp_diff': (datetime.now() - message.timestamp).total_seconds(),
            'header_count': len(message.headers)
        }
    
    async def _process_api_request(self, request_data: Dict) -> Dict:
        """Process the actual API request."""
        # Simulate API processing
        await asyncio.sleep(0.01)  # Simulate processing time
        
        return {
            "status": "success",
            "data": f"Processed request: {request_data.get('action', 'unknown')}",
            "timestamp": datetime.now().isoformat()
        }
    
    def _create_error_response(self, original_message: Message, error_msg: str) -> Message:
        """Create an error response message."""
        return Message(
            id=str(uuid.uuid4()),
            payload=json.dumps({"error": error_msg}).encode(),
            headers={"content-type": "application/json", "status": "400"},
            timestamp=datetime.now(),
            source_agent=self.agent_id,
            destination_agent=original_message.source_agent
        )

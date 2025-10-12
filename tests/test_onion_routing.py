"""
Test suite for the onion routing simulation system.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch
import numpy as np

from src.agents import (
    ClientAgent, EntryNodeAgent, RelayNodeAgent, 
    ExitNodeAgent, APIGatewayAgent, Message, AgentType
)
from src.simulator import OnionRoutingSimulator
from src.ddos_detection import (
    DDoSDetectionSystem, TinyMLModel, FeatureExtractor, NetworkFeatures
)


class TestAgents:
    """Test cases for different agent types."""
    
    def test_client_agent_creation(self):
        """Test client agent initialization."""
        client = ClientAgent("test_client")
        assert client.agent_id == "test_client"
        assert client.agent_type == AgentType.CLIENT
        assert client.is_active is True
    
    def test_entry_node_agent_creation(self):
        """Test entry node agent initialization."""
        entry_node = EntryNodeAgent("test_entry")
        assert entry_node.agent_id == "test_entry"
        assert entry_node.agent_type == AgentType.ENTRY_NODE
    
    def test_relay_node_agent_creation(self):
        """Test relay node agent initialization."""
        relay_node = RelayNodeAgent("test_relay")
        assert relay_node.agent_id == "test_relay"
        assert relay_node.agent_type == AgentType.RELAY_NODE
    
    def test_exit_node_agent_creation(self):
        """Test exit node agent initialization."""
        exit_node = ExitNodeAgent("test_exit")
        assert exit_node.agent_id == "test_exit"
        assert exit_node.agent_type == AgentType.EXIT_NODE
    
    def test_api_gateway_agent_creation(self):
        """Test API gateway agent initialization."""
        gateway = APIGatewayAgent("test_gateway")
        assert gateway.agent_id == "test_gateway"
        assert gateway.agent_type == AgentType.API_GATEWAY
    
    def test_agent_connection(self):
        """Test connection between agents."""
        client = ClientAgent("client1")
        entry_node = EntryNodeAgent("entry1")
        
        client.connect_to_agent(entry_node)
        
        assert "entry1" in client.connected_agents
        assert "client1" in entry_node.connected_agents
    
    @pytest.mark.asyncio
    async def test_onion_request_creation(self):
        """Test creation of onion-encrypted requests."""
        client = ClientAgent("client1")
        entry_node = EntryNodeAgent("entry1")
        relay_node = RelayNodeAgent("relay1")
        
        client.connect_to_agent(entry_node)
        client.connect_to_agent(relay_node)
        
        route = ["entry1", "relay1"]
        payload = "test request"
        
        message = await client.create_onion_request(payload, route)
        
        assert message.source_agent == "client1"
        assert message.route_path == route
        assert len(message.payload) > len(payload.encode())  # Encrypted is larger
    
    @pytest.mark.asyncio 
    async def test_message_processing_chain(self):
        """Test message processing through the chain."""
        # Create a simple chain: client -> entry -> relay -> exit -> gateway
        client = ClientAgent("client1")
        entry_node = EntryNodeAgent("entry1")
        relay_node = RelayNodeAgent("relay1")
        exit_node = ExitNodeAgent("exit1")
        gateway = APIGatewayAgent("gateway1")
        
        # Connect agents
        client.connect_to_agent(entry_node)
        entry_node.connect_to_agent(relay_node)
        relay_node.connect_to_agent(exit_node)
        exit_node.connect_to_agent(gateway)
        
        # Create and send a message
        route = ["entry1", "relay1", "exit1", "gateway1"]
        original_payload = json.dumps({"action": "test", "data": "hello"})
        
        message = await client.create_onion_request(original_payload, route)
        
        # Process through entry node
        processed_message = await entry_node.process_message(message)
        assert processed_message is not None
        assert len(processed_message.payload) < len(message.payload)  # One layer removed


class TestDDoSDetection:
    """Test cases for DDoS detection system."""
    
    def test_feature_extractor(self):
        """Test feature extraction from messages."""
        extractor = FeatureExtractor()
        
        # Create mock message and metrics
        message = Mock()
        message.payload = b"test payload"
        message.timestamp = Mock()
        message.headers = {"content-type": "application/json"}
        
        metrics = Mock()
        metrics.request_count = 50
        
        features = extractor.extract_features_from_message(message, metrics)
        
        assert isinstance(features, NetworkFeatures)
        assert features.packet_rate >= 0
        assert features.byte_rate >= 0
        assert features.payload_entropy >= 0
    
    def test_tinyml_model_creation(self):
        """Test TinyML model initialization."""
        model = TinyMLModel(input_size=10)
        assert model.input_size == 10
        assert model.model is None  # Not trained yet
    
    def test_tinyml_model_training(self):
        """Test TinyML model training with synthetic data."""
        model = TinyMLModel(input_size=10)
        
        # Generate simple synthetic data
        X_train = np.random.random((100, 10))
        y_train = np.random.randint(0, 2, 100)
        X_val = np.random.random((20, 10))
        y_val = np.random.randint(0, 2, 20)
        
        results = model.train(X_train, y_train, X_val, y_val)
        
        assert model.model is not None
        assert 'validation_accuracy' in results
        assert 'model_size_kb' in results
        assert results['model_size_kb'] > 0
    
    def test_ddos_detection_system(self):
        """Test complete DDoS detection system."""
        system = DDoSDetectionSystem()
        
        # Test synthetic data generation
        X, y = system.generate_synthetic_data(1000)
        assert X.shape == (1000, 10)
        assert y.shape == (1000,)
        assert set(y) == {0, 1}  # Binary classification
    
    def test_feature_array_conversion(self):
        """Test conversion of features to array format."""
        extractor = FeatureExtractor()
        
        features = NetworkFeatures(
            packet_rate=10.0,
            byte_rate=1000.0,
            flow_duration=5.0,
            packet_size_variance=0.5,
            protocol_distribution={"http": 1.0},
            port_distribution={80: 1.0},
            timestamp_variance=0.1,
            connection_count=5,
            unique_source_ips=3,
            payload_entropy=4.0
        )
        
        array = extractor.features_to_array(features)
        assert array.shape == (10,)
        assert array[0] == 10.0  # packet_rate
        assert array[1] == 1000.0  # byte_rate


class TestSimulator:
    """Test cases for the main simulator."""
    
    def test_simulator_initialization(self):
        """Test simulator initialization."""
        config = {
            "num_clients": 2,
            "num_entry_nodes": 2,
            "num_relay_nodes": 2,
            "num_exit_nodes": 2,
            "num_api_gateways": 1
        }
        
        simulator = OnionRoutingSimulator(config)
        assert simulator.config == config
        assert len(simulator.clients) == 0  # Not set up yet
    
    @pytest.mark.asyncio
    async def test_network_setup(self):
        """Test network topology setup."""
        config = {
            "num_clients": 2,
            "num_entry_nodes": 2,
            "num_relay_nodes": 2,
            "num_exit_nodes": 2,
            "num_api_gateways": 1
        }
        
        simulator = OnionRoutingSimulator(config)
        await simulator.setup_network()
        
        assert len(simulator.clients) == 2
        assert len(simulator.entry_nodes) == 2
        assert len(simulator.relay_nodes) == 2
        assert len(simulator.exit_nodes) == 2
        assert len(simulator.api_gateways) == 1
        
        # Test connections
        client = simulator.clients[0]
        entry_node = simulator.entry_nodes[0]
        
        assert entry_node.agent_id in client.connected_agents
    
    def test_route_generation(self):
        """Test random route generation."""
        config = {
            "num_clients": 1,
            "num_entry_nodes": 2,
            "num_relay_nodes": 3,
            "num_exit_nodes": 2,
            "num_api_gateways": 1
        }
        
        simulator = OnionRoutingSimulator(config)
        # Need to set up networks first
        simulator.entry_nodes = [Mock(agent_id=f"entry_{i}") for i in range(2)]
        simulator.relay_nodes = [Mock(agent_id=f"relay_{i}") for i in range(3)]
        simulator.exit_nodes = [Mock(agent_id=f"exit_{i}") for i in range(2)]
        simulator.api_gateways = [Mock(agent_id=f"gateway_{i}") for i in range(1)]
        
        route = simulator._generate_random_route()
        
        assert len(route) >= 4  # entry + relay + exit + gateway
        assert route[0].startswith("entry_")
        assert route[-1].startswith("gateway_")


class TestIntegration:
    """Integration tests for the complete system."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_message_flow(self):
        """Test complete message flow from client to gateway."""
        # Setup small network
        config = {
            "num_clients": 1,
            "num_entry_nodes": 1,
            "num_relay_nodes": 1,
            "num_exit_nodes": 1,
            "num_api_gateways": 1
        }
        
        simulator = OnionRoutingSimulator(config)
        await simulator.setup_network()
        
        # Get agents
        client = simulator.clients[0]
        entry_node = simulator.entry_nodes[0]
        relay_node = simulator.relay_nodes[0]
        exit_node = simulator.exit_nodes[0]
        gateway = simulator.api_gateways[0]
        
        # Create request
        route = [entry_node.agent_id, relay_node.agent_id, 
                exit_node.agent_id, gateway.agent_id]
        payload = json.dumps({"action": "test", "data": "integration_test"})
        
        message = await client.create_onion_request(payload, route)
        
        # Process through chain manually
        msg1 = await entry_node.process_message(message)
        assert msg1 is not None
        
        msg2 = await relay_node.process_message(msg1)
        assert msg2 is not None
        
        msg3 = await exit_node.process_message(msg2)
        assert msg3 is not None
        
        # Final processing at gateway
        response = await gateway.process_message(msg3)
        assert response is not None
        
        # Verify response content
        response_data = json.loads(response.payload.decode())
        assert "status" in response_data
    
    @pytest.mark.asyncio 
    async def test_ddos_detection_integration(self):
        """Test DDoS detection integration with agents."""
        # Setup detection system
        detection_system = DDoSDetectionSystem()
        
        # Train a simple model
        X, y = detection_system.generate_synthetic_data(100)
        from sklearn.model_selection import train_test_split
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2)
        
        detection_system.tinyml_model.train(X_train, y_train, X_val, y_val)
        
        # Create relay node with detection
        relay_node = RelayNodeAgent("relay_test")
        relay_node.ddos_detector = detection_system
        
        # Test with mock message
        message = Mock()
        message.id = "test_123"
        message.payload = b"normal traffic"
        message.headers = {"content-type": "application/json"}
        message.timestamp = Mock()
        message.route_path = ["gateway1"]
        
        # Mock metrics
        relay_node.metrics.request_count = 10
        
        # The message should process normally (low traffic)
        with patch.object(relay_node, 'decrypt_payload', return_value=b"decrypted"):
            processed = await relay_node.process_message(message)
            assert processed is not None


if __name__ == "__main__":
    pytest.main([__file__])

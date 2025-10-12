"""
Onion Routing Network Simulator for DDoS-Resilient API Gateway Research.

This module provides the main simulation environment for testing onion routing
with DDoS detection capabilities in edge cloud environments.
"""

import asyncio
import json
import logging
import random
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import numpy as np

from agents import (
    ClientAgent, EntryNodeAgent, RelayNodeAgent, 
    ExitNodeAgent, APIGatewayAgent, Message, TrafficMetrics
)


class OnionRoutingSimulator:
    """Main simulator for the onion routing network."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.clients = []
        self.entry_nodes = []
        self.relay_nodes = []
        self.exit_nodes = []
        self.api_gateways = []
        
        self.simulation_start_time = None
        self.simulation_metrics = TrafficMetrics()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("OnionRoutingSimulator")
    
    async def setup_network(self):
        """Initialize the network topology with agents."""
        self.logger.info("Setting up onion routing network...")
        
        # Create agents based on configuration
        num_clients = self.config.get('num_clients', 5)
        num_entry_nodes = self.config.get('num_entry_nodes', 3)
        num_relay_nodes = self.config.get('num_relay_nodes', 5)
        num_exit_nodes = self.config.get('num_exit_nodes', 3)
        num_api_gateways = self.config.get('num_api_gateways', 2)
        
        # Create client agents
        for i in range(num_clients):
            client = ClientAgent(f"client_{i}")
            self.clients.append(client)
        
        # Create entry node agents
        for i in range(num_entry_nodes):
            entry_node = EntryNodeAgent(f"entry_{i}")
            self.entry_nodes.append(entry_node)
        
        # Create relay node agents
        for i in range(num_relay_nodes):
            relay_node = RelayNodeAgent(f"relay_{i}")
            self.relay_nodes.append(relay_node)
        
        # Create exit node agents
        for i in range(num_exit_nodes):
            exit_node = ExitNodeAgent(f"exit_{i}")
            self.exit_nodes.append(exit_node)
        
        # Create API gateway agents
        for i in range(num_api_gateways):
            api_gateway = APIGatewayAgent(f"gateway_{i}")
            self.api_gateways.append(api_gateway)
        
        # Establish network connections
        await self._establish_connections()
        
        self.logger.info(f"Network setup complete: {num_clients} clients, "
                        f"{num_entry_nodes} entry nodes, {num_relay_nodes} relay nodes, "
                        f"{num_exit_nodes} exit nodes, {num_api_gateways} gateways")
    
    async def _establish_connections(self):
        """Establish connections between different types of agents."""
        # Connect clients to entry nodes
        for client in self.clients:
            for entry_node in self.entry_nodes:
                client.connect_to_agent(entry_node)
        
        # Connect entry nodes to relay nodes
        for entry_node in self.entry_nodes:
            for relay_node in self.relay_nodes:
                entry_node.connect_to_agent(relay_node)
        
        # Connect relay nodes to each other (for multiple hops)
        for i, relay_node in enumerate(self.relay_nodes):
            for j, other_relay in enumerate(self.relay_nodes):
                if i != j:
                    relay_node.connect_to_agent(other_relay)
        
        # Connect relay nodes to exit nodes
        for relay_node in self.relay_nodes:
            for exit_node in self.exit_nodes:
                relay_node.connect_to_agent(exit_node)
        
        # Connect exit nodes to API gateways
        for exit_node in self.exit_nodes:
            for gateway in self.api_gateways:
                exit_node.connect_to_agent(gateway)
    
    def _generate_random_route(self) -> List[str]:
        """Generate a random route through the onion network."""
        # Select random nodes for the route
        entry_node = random.choice(self.entry_nodes).agent_id
        relay_nodes = random.sample(
            [node.agent_id for node in self.relay_nodes], 
            min(2, len(self.relay_nodes))
        )
        exit_node = random.choice(self.exit_nodes).agent_id
        gateway = random.choice(self.api_gateways).agent_id
        
        return [entry_node] + relay_nodes + [exit_node, gateway]
    
    async def simulate_legitimate_traffic(self, duration_seconds: int = 60):
        """Simulate legitimate user traffic through the network."""
        self.logger.info(f"Starting legitimate traffic simulation for {duration_seconds} seconds")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration_seconds)
        
        legitimate_requests = []
        
        while datetime.now() < end_time:
            # Generate legitimate requests from random clients
            client = random.choice(self.clients)
            route = self._generate_random_route()
            
            # Create legitimate API request
            request_payload = {
                "action": random.choice(["get_user", "update_profile", "list_items", "search"]),
                "user_id": random.randint(1000, 9999),
                "timestamp": datetime.now().isoformat()
            }
            
            # Create onion-encrypted message
            message = await client.create_onion_request(
                json.dumps(request_payload), 
                route
            )
            
            # Send the request
            first_hop = route[0]
            task = asyncio.create_task(client.send_message(message, first_hop))
            legitimate_requests.append(task)
            
            # Random delay between requests (simulate real user behavior)
            await asyncio.sleep(random.uniform(0.1, 2.0))
        
        # Wait for all legitimate requests to complete
        await asyncio.gather(*legitimate_requests, return_exceptions=True)
        
        self.logger.info("Legitimate traffic simulation completed")
    
    async def simulate_ddos_attack(self, attack_type: str = "volumetric", 
                                 duration_seconds: int = 30):
        """Simulate different types of DDoS attacks."""
        self.logger.info(f"Starting {attack_type} DDoS attack simulation for {duration_seconds} seconds")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration_seconds)
        
        attack_requests = []
        
        if attack_type == "volumetric":
            # High-volume attack with many requests
            while datetime.now() < end_time:
                # Use fewer clients to simulate botnet behavior
                client = random.choice(self.clients[:2])  
                route = self._generate_random_route()
                
                # Create malicious request (repetitive patterns)
                attack_payload = {
                    "action": "flood_request",
                    "data": "A" * 1000,  # Large payload
                    "timestamp": datetime.now().isoformat()
                }
                
                message = await client.create_onion_request(
                    json.dumps(attack_payload), 
                    route
                )
                
                first_hop = route[0]
                task = asyncio.create_task(client.send_message(message, first_hop))
                attack_requests.append(task)
                
                # Very short delay for high volume
                await asyncio.sleep(0.01)
        
        elif attack_type == "low_rate":
            # Low and slow attack - harder to detect
            while datetime.now() < end_time:
                client = random.choice(self.clients)
                route = self._generate_random_route()
                
                # Slow, persistent connections
                attack_payload = {
                    "action": "slow_request",
                    "data": "slow_attack_pattern",
                    "timestamp": datetime.now().isoformat()
                }
                
                message = await client.create_onion_request(
                    json.dumps(attack_payload), 
                    route
                )
                
                first_hop = route[0]
                task = asyncio.create_task(client.send_message(message, first_hop))
                attack_requests.append(task)
                
                # Longer delay to stay under detection thresholds
                await asyncio.sleep(random.uniform(5.0, 15.0))
        
        # Wait for attack requests to complete
        await asyncio.gather(*attack_requests, return_exceptions=True)
        
        self.logger.info(f"{attack_type} DDoS attack simulation completed")
    
    async def start_all_agents(self):
        """Start all agents in the network."""
        all_agents = (self.clients + self.entry_nodes + 
                     self.relay_nodes + self.exit_nodes + self.api_gateways)
        
        agent_tasks = [asyncio.create_task(agent.start()) for agent in all_agents]
        return agent_tasks
    
    async def run_simulation(self, total_duration: int = 300):
        """Run the complete simulation scenario."""
        self.simulation_start_time = datetime.now()
        self.logger.info(f"Starting onion routing simulation for {total_duration} seconds")
        
        # Start all agents
        agent_tasks = await self.start_all_agents()
        
        try:
            # Phase 1: Baseline legitimate traffic (60 seconds)
            await self.simulate_legitimate_traffic(60)
            
            # Phase 2: Concurrent legitimate traffic and volumetric attack
            legitimate_task = asyncio.create_task(
                self.simulate_legitimate_traffic(60)
            )
            volumetric_attack_task = asyncio.create_task(
                self.simulate_ddos_attack("volumetric", 30)
            )
            await asyncio.gather(legitimate_task, volumetric_attack_task)
            
            # Phase 3: Low-rate attack mixed with legitimate traffic
            legitimate_task = asyncio.create_task(
                self.simulate_legitimate_traffic(90)
            )
            low_rate_attack_task = asyncio.create_task(
                self.simulate_ddos_attack("low_rate", 60)
            )
            await asyncio.gather(legitimate_task, low_rate_attack_task)
            
            # Phase 4: Recovery period with only legitimate traffic
            await self.simulate_legitimate_traffic(90)
            
        finally:
            # Stop all agents
            for client in self.clients:
                client.is_active = False
            for agent in (self.entry_nodes + self.relay_nodes + 
                         self.exit_nodes + self.api_gateways):
                agent.is_active = False
            
            # Cancel agent tasks
            for task in agent_tasks:
                task.cancel()
            
            await asyncio.gather(*agent_tasks, return_exceptions=True)
        
        self.logger.info("Simulation completed")
        
        # Generate final metrics report
        await self._generate_metrics_report()
    
    async def _generate_metrics_report(self):
        """Generate comprehensive metrics report from the simulation."""
        self.logger.info("Generating simulation metrics report...")
        
        total_requests = sum(agent.metrics.request_count 
                           for agent in (self.entry_nodes + self.relay_nodes + 
                                       self.exit_nodes + self.api_gateways))
        
        total_ddos_detected = sum(agent.metrics.ddos_detected_count 
                                for agent in (self.relay_nodes + self.api_gateways))
        
        # Calculate simulation duration
        duration = (datetime.now() - self.simulation_start_time).total_seconds()
        
        metrics_report = {
            "simulation_duration_seconds": duration,
            "total_requests_processed": total_requests,
            "total_ddos_attacks_detected": total_ddos_detected,
            "average_throughput_rps": total_requests / duration if duration > 0 else 0,
            "agent_metrics": {}
        }
        
        # Collect individual agent metrics
        for agent_group, agents in [
            ("clients", self.clients),
            ("entry_nodes", self.entry_nodes),
            ("relay_nodes", self.relay_nodes),
            ("exit_nodes", self.exit_nodes),
            ("api_gateways", self.api_gateways)
        ]:
            metrics_report["agent_metrics"][agent_group] = []
            for agent in agents:
                agent_data = {
                    "agent_id": agent.agent_id,
                    "requests_processed": agent.metrics.request_count,
                    "ddos_detected": agent.metrics.ddos_detected_count,
                    "errors": agent.metrics.error_count
                }
                metrics_report["agent_metrics"][agent_group].append(agent_data)
        
        # Save metrics to file
        with open('/Users/ramygane/AIProjects/ResearchPaper/data/simulation_metrics.json', 'w') as f:
            json.dump(metrics_report, f, indent=2)
        
        self.logger.info("Metrics report saved to data/simulation_metrics.json")
        
        # Print summary
        print("\n" + "="*60)
        print("ONION ROUTING SIMULATION SUMMARY")
        print("="*60)
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total Requests: {total_requests}")
        print(f"DDoS Attacks Detected: {total_ddos_detected}")
        print(f"Average Throughput: {metrics_report['average_throughput_rps']:.2f} RPS")
        print("="*60)


async def main():
    """Main entry point for the simulation."""
    # Default configuration
    config = {
        "num_clients": 5,
        "num_entry_nodes": 3,
        "num_relay_nodes": 5,
        "num_exit_nodes": 3,
        "num_api_gateways": 2,
        "simulation_duration": 300  # 5 minutes
    }
    
    # Initialize and run simulator
    simulator = OnionRoutingSimulator(config)
    await simulator.setup_network()
    await simulator.run_simulation(config["simulation_duration"])


if __name__ == "__main__":
    asyncio.run(main())

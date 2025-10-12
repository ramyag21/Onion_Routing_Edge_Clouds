"""
Main entry point for the Onion Routing DDoS-Resilient API Gateway simulation.

This script demonstrates the complete research implementation including:
- Multi-agent onion routing network
- DDoS attack simulation and detection
- TinyML/LSTM/GRU model comparison
- Explainable AI analysis
"""

import asyncio
import json
import logging
import os
from datetime import datetime
import click

from simulator import OnionRoutingSimulator
from ddos_detection import DDoSDetectionSystem
from agents import RelayNodeAgent, APIGatewayAgent


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/Users/ramygane/AIProjects/ResearchPaper/data/simulation.log'),
            logging.StreamHandler()
        ]
    )


def create_data_directory():
    """Create data directory if it doesn't exist."""
    data_dir = '/Users/ramygane/AIProjects/ResearchPaper/data'
    os.makedirs(data_dir, exist_ok=True)


@click.command()
@click.option('--config', '-c', default='configs/default.yaml', 
              help='Configuration file path')
@click.option('--duration', '-d', default=300, 
              help='Simulation duration in seconds')
@click.option('--clients', default=5, 
              help='Number of client agents')
@click.option('--entry-nodes', default=3, 
              help='Number of entry node agents')
@click.option('--relay-nodes', default=5, 
              help='Number of relay node agents')
@click.option('--exit-nodes', default=3, 
              help='Number of exit node agents')
@click.option('--gateways', default=2, 
              help='Number of API gateway agents')
@click.option('--train-models', is_flag=True, 
              help='Train DDoS detection models before simulation')
@click.option('--log-level', default='INFO', 
              help='Logging level (DEBUG, INFO, WARNING, ERROR)')
def main(config, duration, clients, entry_nodes, relay_nodes, exit_nodes, 
         gateways, train_models, log_level):
    """
    Run the Onion Routing DDoS-Resilient API Gateway simulation.
    
    This comprehensive simulation demonstrates:
    1. Multi-agent onion routing with encryption layers
    2. DDoS attack generation and detection
    3. TinyML-based lightweight ML models for edge deployment
    4. Explainable AI for security analyst insights
    5. Performance metrics and analysis
    """
    
    # Setup
    setup_logging(log_level)
    create_data_directory()
    
    logger = logging.getLogger("MainSimulation")
    logger.info("Starting Onion Routing DDoS-Resilient API Gateway Simulation")
    
    # Configuration
    simulation_config = {
        "num_clients": clients,
        "num_entry_nodes": entry_nodes,
        "num_relay_nodes": relay_nodes,
        "num_exit_nodes": exit_nodes,
        "num_api_gateways": gateways,
        "simulation_duration": duration
    }
    
    logger.info(f"Configuration: {simulation_config}")
    
    # Train DDoS detection models if requested
    if train_models:
        logger.info("Training DDoS detection models...")
        detection_system = DDoSDetectionSystem()
        training_results = detection_system.train_all_models()
        
        # Save training results
        with open('/Users/ramygane/AIProjects/ResearchPaper/data/model_training_results.json', 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            serializable_results = {}
            for model_name, results in training_results.items():
                if model_name == 'explainability':
                    serializable_results[model_name] = results
                else:
                    serializable_results[model_name] = {
                        key: (value if not hasattr(value, 'tolist') else value.tolist())
                        for key, value in results.items()
                    }
            
            json.dump(serializable_results, f, indent=2, default=str)
        
        logger.info("Model training completed. Results saved to data/model_training_results.json")
        
        # Print training summary
        print("\n" + "="*60)
        print("MODEL TRAINING RESULTS")
        print("="*60)
        for model_name, results in training_results.items():
            if model_name != 'explainability':
                print(f"{model_name.upper()}:")
                print(f"  Accuracy: {results['validation_accuracy']:.4f}")
                print(f"  Precision: {results['validation_precision']:.4f}")
                print(f"  Recall: {results['validation_recall']:.4f}")
                if 'model_size_kb' in results:
                    print(f"  Model Size: {results['model_size_kb']:.2f} KB")
                print()
        print("="*60)
    
    # Run the main simulation
    async def run_simulation():
        simulator = OnionRoutingSimulator(simulation_config)
        
        # Integrate DDoS detection into agents if models were trained
        if train_models:
            logger.info("Integrating DDoS detection into network agents...")
            await simulator.setup_network()
            
            # Add DDoS detection to relay nodes and API gateways
            for relay_node in simulator.relay_nodes:
                relay_node.ddos_detector = detection_system
            
            for gateway in simulator.api_gateways:
                gateway.ddos_detector = detection_system
        else:
            await simulator.setup_network()
        
        # Run the simulation
        await simulator.run_simulation(duration)
    
    # Execute the simulation
    try:
        asyncio.run(run_simulation())
        logger.info("Simulation completed successfully")
        
        print("\n" + "="*60)
        print("SIMULATION COMPLETED SUCCESSFULLY")
        print("="*60)
        print("Check the following files for results:")
        print("- data/simulation_metrics.json - Performance metrics")
        print("- data/simulation.log - Detailed logs")
        if train_models:
            print("- data/model_training_results.json - ML model results")
        print("="*60)
        
    except Exception as e:
        logger.error(f"Simulation failed: {e}")
        raise


@click.command()
@click.option('--model-type', default='tinyml', 
              type=click.Choice(['tinyml', 'lstm', 'gru', 'all']),
              help='Type of ML model to train and evaluate')
def train_models(model_type):
    """Train and evaluate DDoS detection models."""
    setup_logging()
    create_data_directory()
    
    logger = logging.getLogger("ModelTraining")
    logger.info(f"Training {model_type} model(s) for DDoS detection")
    
    detection_system = DDoSDetectionSystem()
    
    if model_type == 'all':
        results = detection_system.train_all_models()
    else:
        # Train specific model
        X, y = detection_system.generate_synthetic_data(10000)
        from sklearn.model_selection import train_test_split
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        
        if model_type == 'tinyml':
            results = {'tinyml': detection_system.tinyml_model.train(X_train, y_train, X_val, y_val)}
        elif model_type == 'lstm':
            results = {'lstm': detection_system.lstm_model.train(X_train, y_train, X_val, y_val)}
        elif model_type == 'gru':
            results = {'gru': detection_system.gru_model.train(X_train, y_train, X_val, y_val)}
    
    # Save results
    with open(f'/Users/ramygane/AIProjects/ResearchPaper/data/{model_type}_training_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info(f"Training completed. Results saved to data/{model_type}_training_results.json")


@click.command()
@click.option('--attack-type', default='volumetric',
              type=click.Choice(['volumetric', 'low_rate', 'mixed']),
              help='Type of DDoS attack to simulate')
@click.option('--duration', default=60,
              help='Attack duration in seconds')
def simulate_attack(attack_type, duration):
    """Simulate specific DDoS attack patterns."""
    setup_logging()
    create_data_directory()
    
    logger = logging.getLogger("AttackSimulation")
    logger.info(f"Simulating {attack_type} DDoS attack for {duration} seconds")
    
    async def run_attack_simulation():
        config = {
            "num_clients": 3,
            "num_entry_nodes": 2,
            "num_relay_nodes": 3,
            "num_exit_nodes": 2,
            "num_api_gateways": 1,
            "simulation_duration": duration
        }
        
        simulator = OnionRoutingSimulator(config)
        await simulator.setup_network()
        
        if attack_type == 'volumetric':
            await simulator.simulate_ddos_attack('volumetric', duration)
        elif attack_type == 'low_rate':
            await simulator.simulate_ddos_attack('low_rate', duration)
        elif attack_type == 'mixed':
            # Run both attack types concurrently
            vol_task = asyncio.create_task(
                simulator.simulate_ddos_attack('volumetric', duration // 2)
            )
            lr_task = asyncio.create_task(
                simulator.simulate_ddos_attack('low_rate', duration)
            )
            await asyncio.gather(vol_task, lr_task)
    
    asyncio.run(run_attack_simulation())
    logger.info("Attack simulation completed")


# CLI interface
@click.group()
def cli():
    """Onion Routing DDoS-Resilient API Gateway Research Tools."""
    pass


cli.add_command(main, name='simulate')
cli.add_command(train_models, name='train')
cli.add_command(simulate_attack, name='attack')


if __name__ == "__main__":
    cli()

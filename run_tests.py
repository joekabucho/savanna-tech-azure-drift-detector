#!/usr/bin/env python3
"""
Test runner script for the Azure Drift Detector application.
Executes all test suites and generates a report.
"""

import os
import sys
import pytest
import argparse
from datetime import datetime


def setup_test_environment():
    """Set up environment variables for testing."""
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['TESTING'] = 'True'
    
    if 'SQLALCHEMY_DATABASE_URI' not in os.environ:
        os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    os.environ['SESSION_SECRET'] = 'test_secret_key'


def run_tests(verbosity=1, test_dir='tests', specific_test=None):
    """Run tests using pytest."""
    setup_test_environment()
    
    if specific_test:
        test_path = os.path.join(test_dir, specific_test)
    else:
        test_path = test_dir
        args = [
        '-v' * verbosity,  
        '--no-header',     
        test_path,       
    ]
    
    return pytest.main(args)


def generate_report(exit_code):
    """Generate a simple report based on test results."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    report = f"""
Azure Drift Detector - Test Report
=================================
Timestamp: {timestamp}
Result: {"PASSED" if exit_code == 0 else "FAILED"}
Exit Code: {exit_code}
=================================
"""
    print(report)
    
    with open('test_report.txt', 'w') as f:
        f.write(report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run tests for Azure Drift Detector')
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        help='Increase verbosity (can be used multiple times)')
    parser.add_argument('-t', '--test', help='Run a specific test file', default=None)
    args = parser.parse_args()
    
    print(f"Running {'specific test: ' + args.test if args.test else 'all tests'}")
    
    exit_code = run_tests(verbosity=args.verbose, specific_test=args.test)
    generate_report(exit_code)
    
    sys.exit(exit_code)
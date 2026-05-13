#!/usr/bin/env bash

# IDS Sentinel - Production Startup Script
# This script starts the dashboard using Gunicorn (WSGI Server) instead of the Flask development server.
# This ensures it can handle concurrent requests and runs much faster.

echo "Starting IDS Sentinel Dashboard (Production Mode)"
echo "Using Gunicorn WSGI Server with 4 worker threads."
echo "Access the dashboard at http://127.0.0.1:8080"
echo "Press Ctrl+C to stop the server."

# macOS fix: Prevent Objective-C runtime from crashing in Gunicorn worker forks
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

# Run gunicorn, binding to port 8080, using 4 worker processes
.venv/bin/gunicorn -w 4 -b 0.0.0.0:8080 app:app

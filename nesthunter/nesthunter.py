"""
NestHunter - Nested Archive Extraction & Malware Pattern Analysis Tool

A security tool that recursively extracts nested archives and detects
suspicious patterns commonly used in malware delivery.

Usage:
    python nesthunter.py [--port PORT] [--host HOST] [--debug]

Example:
    python nesthunter.py --port 5000 --debug
"""

import argparse
import sys
import os

# Add web directory to path for imports
web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')
sys.path.insert(0, web_dir)

from app import app


def main():
    parser = argparse.ArgumentParser(
        description='NestHunter - Nested Archive Extraction & Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nesthunter.py                    # Start server on localhost:5000
  python nesthunter.py --port 8080        # Use custom port
  python nesthunter.py --host 0.0.0.0     # Allow external connections
  python nesthunter.py --debug            # Enable debug mode

Supported Archive Formats:
  ZIP, RAR, 7z, ISO, VHD, TAR, GZ, TAR.GZ
        """
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5000,
        help='Port to run the server on (default: 5000)'
    )
    
    parser.add_argument(
        '--host', '-H',
        type=str,
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1, use 0.0.0.0 for all interfaces)'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║                      NestHunter                           ║
        ║         Nested Archive Extraction & Analysis Tool         ║
        ╚═══════════════════════════════════════════════════════════╝
        """)
    print(f"  🌐 Starting server at http://{args.host}:{args.port}")
    print(f"  Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"  Max file size: 500MB")
    print(f"  📁 Supported formats: ZIP, RAR, 7z, ISO, VHD, TAR, GZ")
    print(f"  🔍 Debug mode: {'ON' if args.debug else 'OFF'}")
    print()
    print("  Press Ctrl+C to stop the server")
    print()
    
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        sys.exit(0)


if __name__ == '__main__':
    main()

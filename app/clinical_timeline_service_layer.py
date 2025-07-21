"""Service Layer Architecture version of Clinical Timeline App.

This is the main entry point that demonstrates the service layer pattern.
Compare this with clinical_timeline.py to see the architectural differences.

To run this version:
    streamlit run clinical_timeline_service_layer.py

Key architectural improvements:
- Clear separation of concerns
- Testable business logic 
- UI components are pure presentation
- Data access is abstracted
- Dependency injection pattern
"""
import sys
import os

# Add the service_layer package to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from service_layer.main import main

if __name__ == "__main__":
    main()
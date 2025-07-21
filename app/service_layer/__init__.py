"""Service Layer Architecture for Clinical Timeline App.

This package demonstrates clean separation of concerns:
- models/: Data models and entities
- repositories/: Data access layer 
- services/: Business logic layer
- pages/: UI presentation layer
- main.py: Application orchestrator

Key benefits:
- Testable business logic (services can be unit tested)
- UI is separated from business logic
- Data access is abstracted
- Clear dependency injection
- Easy to extend and maintain
"""
from .main import ClinicalTimelineApp

__all__ = ["ClinicalTimelineApp"]
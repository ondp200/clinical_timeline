"""Viewer page - UI components for viewer role users."""
import streamlit as st


class ViewerPage:
    """Viewer dashboard UI - minimal functionality for viewer role."""
    
    def render(self) -> None:
        """Render the viewer dashboard."""
        st.subheader("📁 Viewer Dashboard")
        st.markdown("- View clinical timelines")
        st.markdown("- Export patient reports")
        st.info("Additional viewer features coming soon...")
        
        # Could add viewer-specific functionality here
        # For example: limited data views, read-only access to certain features
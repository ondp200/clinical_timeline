"""Timeline page - pure UI for displaying clinical timelines."""
import streamlit as st
from ..services import TimelineDataService, TimelineVisualizationService


class TimelinePage:
    """Timeline visualization page - pure UI, delegates to services."""
    
    def __init__(self, timeline_data_service: TimelineDataService, 
                 timeline_viz_service: TimelineVisualizationService):
        self.timeline_data_service = timeline_data_service
        self.timeline_viz_service = timeline_viz_service
    
    def render(self) -> None:
        """Render the timeline page."""
        st.subheader("Interactive Clinical Timeline")
        
        # Get timeline data from service
        timeline_data = self.timeline_data_service.get_sample_timeline_data()
        
        # Create visualization using service
        timeline_chart = self.timeline_viz_service.create_timeline_chart(timeline_data)
        
        # Display chart
        st.plotly_chart(timeline_chart, use_container_width=True)
        
        # Optional: Add timeline summary
        self._render_timeline_summary(timeline_data)
    
    def _render_timeline_summary(self, timeline_data) -> None:
        """Render timeline summary information."""
        with st.expander("Timeline Summary"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Stays", len(timeline_data.inpatient_stays))
            
            with col2:
                total_days = sum(stay.duration_days for stay in timeline_data.inpatient_stays)
                st.metric("Total Inpatient Days", total_days)
            
            with col3:
                st.metric("Total Medications", len(timeline_data.medications))
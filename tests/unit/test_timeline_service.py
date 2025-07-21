"""
Timeline Service Unit Tests

Purpose: Test timeline data processing and visualization business logic
Scope: TimelineDataService and TimelineVisualizationService classes  
Dependencies: No external dependencies (pure business logic)

Test Categories:
1. Timeline data generation and structure
2. Chart creation and configuration
3. Data model validation
4. Visualization components
"""

import pytest
from datetime import datetime, timedelta
import pandas as pd
import plotly.graph_objects as go
from service_layer.services import TimelineDataService, TimelineVisualizationService
from service_layer.models import TimelineData, InpatientStay, MedicationEvent, DiagnosisEvent


class TestTimelineDataService:
    """Test suite for timeline data generation and management."""
    
    def test_get_sample_timeline_data_returns_complete_structure(self, timeline_service):
        """
        Test: Sample timeline data contains all required components
        
        Given: TimelineDataService instance
        When: get_sample_timeline_data() is called
        Then: Returns TimelineData with all components populated
        """
        # Act
        timeline = timeline_service.get_sample_timeline_data()
        
        # Assert
        assert isinstance(timeline, TimelineData)
        assert timeline.patient_id == "sample_patient"
        assert timeline.illness_start is not None
        assert timeline.illness_end is not None
        assert timeline.illness_start < timeline.illness_end
        assert len(timeline.inpatient_stays) == 6
        assert len(timeline.medications) == 3
        assert len(timeline.diagnoses) == 3
    
    def test_timeline_data_illness_duration_is_15_years(self, timeline_service):
        """
        Test: Illness duration spans 15 years as expected
        
        Given: Generated timeline data
        When: Checking illness start and end dates
        Then: Duration is approximately 15 years
        """
        # Act
        timeline = timeline_service.get_sample_timeline_data()
        
        # Assert
        duration = timeline.illness_end - timeline.illness_start
        duration_years = duration.days / 365.25
        assert 14.9 <= duration_years <= 15.1  # Allow for slight variance
    
    def test_inpatient_stays_have_valid_dates(self, timeline_service):
        """
        Test: All inpatient stays have valid admission/discharge dates
        
        Given: Generated timeline data
        When: Examining inpatient stays
        Then: All stays have admission before discharge dates
        And: All dates are within illness timeframe
        """
        # Act
        timeline = timeline_service.get_sample_timeline_data()
        
        # Assert
        for stay in timeline.inpatient_stays:
            assert isinstance(stay, InpatientStay)
            assert stay.admission_date < stay.discharge_date
            assert timeline.illness_start <= stay.admission_date <= timeline.illness_end
            assert timeline.illness_start <= stay.discharge_date <= timeline.illness_end
            assert stay.duration_days > 0
    
    def test_medications_have_valid_structure(self, timeline_service):
        """
        Test: All medication events have valid structure and data
        
        Given: Generated timeline data
        When: Examining medication events
        Then: All medications have date, medication name, and dosage
        And: String representation works correctly
        """
        # Act
        timeline = timeline_service.get_sample_timeline_data()
        
        # Assert
        for medication in timeline.medications:
            assert isinstance(medication, MedicationEvent)
            assert medication.date is not None
            assert medication.medication is not None
            assert medication.dosage is not None
            assert timeline.illness_start <= medication.date <= timeline.illness_end
            # Test string representation
            str_repr = str(medication)
            assert medication.medication in str_repr
            assert medication.dosage in str_repr
    
    def test_diagnoses_have_valid_structure(self, timeline_service):
        """
        Test: All diagnosis events have valid structure and data
        
        Given: Generated timeline data
        When: Examining diagnosis events
        Then: All diagnoses have date, code, and name
        And: String representation shows abbreviated code
        """
        # Act
        timeline = timeline_service.get_sample_timeline_data()
        
        # Assert
        for diagnosis in timeline.diagnoses:
            assert isinstance(diagnosis, DiagnosisEvent)
            assert diagnosis.date is not None
            assert diagnosis.diagnosis_code is not None
            assert diagnosis.diagnosis_name is not None
            assert timeline.illness_start <= diagnosis.date <= timeline.illness_end
            # Test string representation
            str_repr = str(diagnosis)
            assert "Dx:" in str_repr
            assert diagnosis.diagnosis_code in str_repr
    
    def test_timeline_dataframe_conversion(self, timeline_service):
        """
        Test: Timeline data converts correctly to DataFrame
        
        Given: Generated timeline data
        When: to_dataframe() is called
        Then: Returns DataFrame with correct structure
        And: Contains all inpatient stay data
        """
        # Act
        timeline = timeline_service.get_sample_timeline_data()
        df = timeline.to_dataframe()
        
        # Assert
        assert isinstance(df, pd.DataFrame)
        assert len(df) == len(timeline.inpatient_stays)
        assert "Stay" in df.columns
        assert "Admission" in df.columns
        assert "Discharge" in df.columns
        assert df["Stay"].tolist() == [1, 2, 3, 4, 5, 6]


class TestTimelineVisualizationService:
    """Test suite for timeline chart creation and visualization."""
    
    def test_create_timeline_chart_returns_plotly_figure(self, timeline_service):
        """
        Test: Timeline chart creation produces valid Plotly figure
        
        Given: Timeline data and visualization service
        When: create_timeline_chart() is called
        Then: Returns Plotly Figure object
        And: Figure has expected title and layout
        """
        # Arrange
        data_service = timeline_service
        viz_service = TimelineVisualizationService()
        timeline_data = data_service.get_sample_timeline_data()
        
        # Act
        chart = viz_service.create_timeline_chart(timeline_data)
        
        # Assert
        assert isinstance(chart, go.Figure)
        assert chart.layout.title.text == "Course of Illness with Diagnoses, Medications, and Inpatient Stays"
        assert chart.layout.xaxis.title.text == "Date"
        assert chart.layout.width == 1000
        assert chart.layout.height == 520
    
    def test_chart_contains_inpatient_stay_shapes(self, timeline_service):
        """
        Test: Chart includes rectangle shapes for inpatient stays
        
        Given: Timeline data with inpatient stays
        When: Chart is created
        Then: Chart contains rectangle shapes for each stay
        And: Each shape spans from admission to discharge
        """
        # Arrange
        data_service = timeline_service
        viz_service = TimelineVisualizationService()
        timeline_data = data_service.get_sample_timeline_data()
        
        # Act
        chart = viz_service.create_timeline_chart(timeline_data)
        
        # Assert
        shapes = chart.layout.shapes
        stay_shapes = [s for s in shapes if s.type == "rect"]
        assert len(stay_shapes) == len(timeline_data.inpatient_stays)
        
        # Verify shape properties
        for shape in stay_shapes:
            assert shape.fillcolor == "LightSkyBlue"
            assert shape.y0 == 0.9
            assert shape.y1 == 1.1
    
    def test_chart_contains_illness_trajectory_trace(self, timeline_service):
        """
        Test: Chart includes illness trajectory line
        
        Given: Timeline data with illness start/end
        When: Chart is created
        Then: Chart contains line trace for illness trajectory
        And: Line spans from illness start to end
        """
        # Arrange
        data_service = timeline_service
        viz_service = TimelineVisualizationService()
        timeline_data = data_service.get_sample_timeline_data()
        
        # Act
        chart = viz_service.create_timeline_chart(timeline_data)
        
        # Assert
        traces = chart.data
        line_traces = [t for t in traces if t.mode == "lines"]
        assert len(line_traces) >= 1
        
        # Find illness trajectory trace
        illness_trace = next(t for t in line_traces if t.name == "Course of Illness")
        assert illness_trace.line.color == "black"
        assert illness_trace.line.width == 2
    
    def test_chart_contains_annotations_for_all_events(self, timeline_service):
        """
        Test: Chart includes annotations for diagnoses and medications
        
        Given: Timeline data with diagnoses and medications
        When: Chart is created
        Then: Chart contains annotations for all events
        And: Annotations have correct colors and positioning
        """
        # Arrange
        data_service = timeline_service
        viz_service = TimelineVisualizationService()
        timeline_data = data_service.get_sample_timeline_data()
        
        # Act
        chart = viz_service.create_timeline_chart(timeline_data)
        
        # Assert
        annotations = chart.layout.annotations
        
        # Count different types of annotations
        diagnosis_annotations = [a for a in annotations if a.get('arrowcolor') == 'darkred']
        medication_annotations = [a for a in annotations if a.get('arrowcolor') == 'darkgreen']
        legend_annotations = [a for a in annotations if 'Legend' in a.get('text', '')]
        
        assert len(diagnosis_annotations) == len(timeline_data.diagnoses)
        assert len(medication_annotations) == len(timeline_data.medications)
        assert len(legend_annotations) == 2  # Medication and diagnosis legends
    
    def test_chart_layout_configuration(self, timeline_service):
        """
        Test: Chart layout is configured correctly for clinical timeline
        
        Given: Generated timeline chart
        When: Examining layout properties
        Then: Layout has correct axis configuration
        And: Range selectors are present
        And: Y-axis is hidden as expected
        """
        # Arrange
        data_service = timeline_service
        viz_service = TimelineVisualizationService()
        timeline_data = data_service.get_sample_timeline_data()
        
        # Act
        chart = viz_service.create_timeline_chart(timeline_data)
        
        # Assert
        layout = chart.layout
        
        # X-axis configuration
        assert layout.xaxis.type == "date"
        assert layout.xaxis.tickformat == "%Y-%m-%d"
        assert layout.xaxis.showgrid == True
        assert layout.xaxis.rangeslider.visible == True
        assert len(layout.xaxis.rangeselector.buttons) == 4
        
        # Y-axis configuration
        assert layout.yaxis.visible == False
        assert layout.yaxis.range == [0.7, 1.35]
        
        # Other layout properties
        assert layout.margin.b == 360  # Bottom margin for legends
        assert layout.showlegend == False
    
    def test_chart_range_selectors_configuration(self, timeline_service):
        """
        Test: Chart has correctly configured range selector buttons
        
        Given: Generated timeline chart
        When: Examining range selector buttons
        Then: Contains 6m, 1y, 5y, and all buttons
        And: Buttons have correct step configurations
        """
        # Arrange
        data_service = timeline_service
        viz_service = TimelineVisualizationService()
        timeline_data = data_service.get_sample_timeline_data()
        
        # Act
        chart = viz_service.create_timeline_chart(timeline_data)
        
        # Assert
        buttons = chart.layout.xaxis.rangeselector.buttons
        
        # Check button configurations
        six_month_button = next(b for b in buttons if b.label == "6m")
        assert six_month_button.count == 6
        assert six_month_button.step == "month"
        
        one_year_button = next(b for b in buttons if b.label == "1y")
        assert one_year_button.count == 1
        assert one_year_button.step == "year"
        
        five_year_button = next(b for b in buttons if b.label == "5y")
        assert five_year_button.count == 5
        assert five_year_button.step == "year"
        
        all_button = next(b for b in buttons if b.step == "all")
        assert all_button is not None
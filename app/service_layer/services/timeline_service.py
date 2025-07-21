"""Timeline service - pure business logic for clinical timeline data."""
from datetime import datetime, timedelta
from typing import List
import pandas as pd
import plotly.graph_objects as go
from ..models import TimelineData, InpatientStay, MedicationEvent, DiagnosisEvent


class TimelineDataService:
    """Service for managing clinical timeline data."""
    
    def get_sample_timeline_data(self) -> TimelineData:
        """Get sample clinical timeline data."""
        # Define illness period
        illness_start = pd.to_datetime("2010-05-31")
        illness_end = illness_start + pd.DateOffset(years=15)
        
        # Create inpatient stays
        stay_data = [
            (1, "2010-12-10", "2011-02-21"),
            (2, "2012-02-10", "2012-04-28"),
            (3, "2013-06-15", "2013-09-19"),
            (4, "2015-06-14", "2015-09-19"),
            (5, "2017-06-08", "2017-09-19"),
            (6, "2020-06-08", "2020-09-19")
        ]
        
        inpatient_stays = [
            InpatientStay(
                stay_id=stay_id,
                admission_date=pd.to_datetime(admission),
                discharge_date=pd.to_datetime(discharge)
            )
            for stay_id, admission, discharge in stay_data
        ]
        
        # Create medication events
        medications = [
            MedicationEvent(illness_start, "Risperidone", "2 mg"),
            MedicationEvent(pd.to_datetime("2010-12-11"), "Risperidone", "3 mg"),
            MedicationEvent(pd.to_datetime("2010-12-15"), "Risperidone", "4 mg"),
        ]
        
        # Create diagnosis events
        diagnoses = [
            DiagnosisEvent(illness_start, "P-NOS", "Psychosis NOS"),
            DiagnosisEvent(illness_start + timedelta(days=350), "Sz", "Schizophrenia"),
            DiagnosisEvent(illness_start + timedelta(days=736), "SAD", "Schizoaffective Disorder"),
        ]
        
        return TimelineData(
            patient_id="sample_patient",
            illness_start=illness_start,
            illness_end=illness_end,
            inpatient_stays=inpatient_stays,
            medications=medications,
            diagnoses=diagnoses
        )


class TimelineVisualizationService:
    """Service for creating timeline visualizations."""
    
    def create_timeline_chart(self, timeline_data: TimelineData) -> go.Figure:
        """Create Plotly timeline chart from timeline data."""
        fig = go.Figure()
        
        # Add inpatient stays
        self._add_inpatient_stays(fig, timeline_data.inpatient_stays)
        
        # Add illness trajectory
        self._add_illness_trajectory(fig, timeline_data.illness_start, timeline_data.illness_end)
        
        # Create annotations
        annotations = self._create_annotations(timeline_data)
        
        # Configure layout
        self._configure_layout(fig, timeline_data.illness_start, timeline_data.illness_end, annotations)
        
        return fig
    
    def _add_inpatient_stays(self, fig: go.Figure, stays: List[InpatientStay]) -> None:
        """Add inpatient stay rectangles to the plot."""
        for stay in stays:
            fig.add_shape(
                type="rect",
                x0=stay.admission_date, x1=stay.discharge_date,
                y0=0.9, y1=1.1,
                line=dict(color="RoyalBlue"),
                fillcolor="LightSkyBlue",
                opacity=0.6
            )
            fig.add_annotation(
                x=stay.admission_date + (stay.discharge_date - stay.admission_date) / 2,
                y=1.15,
                text=f"Stay {stay.stay_id} ({stay.duration_days} days)",
                showarrow=False,
                font=dict(size=10)
            )
    
    def _add_illness_trajectory(self, fig: go.Figure, start: datetime, end: datetime) -> None:
        """Add illness trajectory line."""
        fig.add_trace(go.Scatter(
            x=[start, end], y=[1, 1],
            mode='lines',
            line=dict(color='black', width=2),
            name='Course of Illness',
            hoverinfo='skip'
        ))
    
    def _create_annotations(self, timeline_data: TimelineData) -> List[dict]:
        """Create diagnosis and medication annotations."""
        annotations = []
        
        # Diagnosis annotations
        for diagnosis in timeline_data.diagnoses:
            annotations.append(dict(
                x=diagnosis.date, y=1.25, text=str(diagnosis),
                showarrow=True, arrowhead=2, ax=0, ay=-40,
                arrowcolor="darkred", font=dict(size=10, color="darkred")
            ))
        
        # Medication annotations  
        for medication in timeline_data.medications:
            annotations.append(dict(
                x=medication.date, y=0.78, text=str(medication),
                showarrow=True, arrowhead=2, ax=0, ay=40,
                arrowcolor="darkgreen", font=dict(size=10, color="darkgreen")
            ))
        
        # Add legends
        annotations.extend(self._create_legends())
        
        return annotations
    
    def _create_legends(self) -> List[dict]:
        """Create legend annotations."""
        return [
            dict(
                xref="paper", yref="paper", x=0.01, y=-0.75,
                text="<b>Medication Legend:</b><br>R = Risperidone",
                showarrow=False, align="left",
                font=dict(size=11, color="darkgreen"),
                bordercolor="darkgreen", borderwidth=1,
                bgcolor="lightyellow"
            ),
            dict(
                xref="paper", yref="paper", x=0.3, y=-0.75,
                text="<b>Diagnosis Legend:</b><br>Dx: P-NOS = Psychosis NOS<br>Dx: Sz = Schizophrenia<br>Dx: SAD = Schizoaffective Disorder",
                showarrow=False, align="left",
                font=dict(size=11, color="darkred"),
                bordercolor="darkred", borderwidth=1,
                bgcolor="lavenderblush"
            )
        ]
    
    def _configure_layout(self, fig: go.Figure, start: datetime, end: datetime, 
                         annotations: List[dict]) -> None:
        """Configure the plot layout."""
        fig.update_layout(
            title="Course of Illness with Diagnoses, Medications, and Inpatient Stays",
            width=1000, height=520,
            xaxis_title="Date",
            yaxis=dict(visible=False, range=[0.7, 1.35]),
            xaxis=dict(
                range=[start, end],
                type='date',
                tickformat="%Y-%m-%d",
                showgrid=True,
                rangeslider=dict(visible=True),
                rangeselector=dict(buttons=[
                    dict(count=6, label="6m", step="month", stepmode="backward"),
                    dict(count=1, label="1y", step="year", stepmode="backward"),
                    dict(count=5, label="5y", step="year", stepmode="backward"),
                    dict(step="all")
                ])
            ),
            margin=dict(b=360),
            annotations=annotations,
            showlegend=False
        )
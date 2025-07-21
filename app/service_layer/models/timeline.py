"""Timeline data models."""
from dataclasses import dataclass
from datetime import datetime
from typing import List, Tuple
import pandas as pd


@dataclass
class InpatientStay:
    """Represents an inpatient hospital stay."""
    stay_id: int
    admission_date: datetime
    discharge_date: datetime
    
    @property
    def duration_days(self) -> int:
        """Calculate stay duration in days."""
        return (self.discharge_date - self.admission_date).days


@dataclass
class MedicationEvent:
    """Represents a medication dosage event."""
    date: datetime
    medication: str
    dosage: str
    
    def __str__(self) -> str:
        """String representation for display."""
        return f"{self.medication} {self.dosage}"


@dataclass
class DiagnosisEvent:
    """Represents a diagnosis event."""
    date: datetime
    diagnosis_code: str
    diagnosis_name: str
    
    def __str__(self) -> str:
        """String representation for display."""
        return f"Dx: {self.diagnosis_code}"


@dataclass
class TimelineData:
    """Complete timeline data for a patient."""
    patient_id: str
    illness_start: datetime
    illness_end: datetime
    inpatient_stays: List[InpatientStay]
    medications: List[MedicationEvent]
    diagnoses: List[DiagnosisEvent]
    
    def to_dataframe(self) -> pd.DataFrame:
        """Convert inpatient stays to DataFrame for plotting."""
        data = {
            "Stay": [stay.stay_id for stay in self.inpatient_stays],
            "Admission": [stay.admission_date for stay in self.inpatient_stays],
            "Discharge": [stay.discharge_date for stay in self.inpatient_stays]
        }
        return pd.DataFrame(data)
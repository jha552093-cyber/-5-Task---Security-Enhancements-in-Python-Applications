"""
Data models for the MedSecure Healthcare Portal (Baseline Application).
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    role: str  # admin, doctor, patient
    email: str


@dataclass
class PatientRecord:
    id: int
    patient_name: str
    ssn: str
    date_of_birth: str
    diagnosis: str
    credit_card: str
    doctor_notes: str
    created_by: int  # user id

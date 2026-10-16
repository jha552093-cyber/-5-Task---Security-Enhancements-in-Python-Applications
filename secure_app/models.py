"""
Data models for MedSecure Application (Secure Implementation).
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
from .crypto import mask_ssn, mask_credit_card, decrypt_field


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    role: str  # admin, doctor, nurse, patient
    email: str
    failed_attempts: int = 0
    locked_until: Optional[float] = None

    def to_safe_dict(self) -> Dict[str, Any]:
        """Returns safe user representation without password hash."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "email": self.email
        }


@dataclass
class PatientRecord:
    id: int
    patient_name: str
    ssn_encrypted: str
    date_of_birth: str
    diagnosis_encrypted: str
    credit_card_encrypted: str
    doctor_notes: str
    created_by: int

    def to_dict(self, include_decrypted: bool = False) -> Dict[str, Any]:
        """
        Returns serialized record. If include_decrypted is False, masks sensitive PII.
        """
        decrypted_ssn = decrypt_field(self.ssn_encrypted)
        decrypted_diag = decrypt_field(self.diagnosis_encrypted)
        decrypted_cc = decrypt_field(self.credit_card_encrypted)

        if include_decrypted:
            return {
                "id": self.id,
                "patient_name": self.patient_name,
                "ssn": decrypted_ssn,
                "date_of_birth": self.date_of_birth,
                "diagnosis": decrypted_diag,
                "credit_card": decrypted_cc,
                "doctor_notes": self.doctor_notes,
                "created_by": self.created_by
            }
        else:
            return {
                "id": self.id,
                "patient_name": self.patient_name,
                "ssn": mask_ssn(decrypted_ssn),
                "date_of_birth": self.date_of_birth,
                "diagnosis": decrypted_diag,  # Clinical diagnosis visible to staff
                "credit_card": mask_credit_card(decrypted_cc),
                "doctor_notes": self.doctor_notes,
                "created_by": self.created_by
            }

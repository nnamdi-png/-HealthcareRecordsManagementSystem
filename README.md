
# Healthcare Records Management System

A secure and private blockchain-based system for managing medical records with strong patient consent controls.

## Overview

This smart contract implements a decentralized **Healthcare Records Management System** designed to securely store and manage medical records. It ensures privacy, access control, and patient consent for healthcare data sharing between patients and authorized providers.

Key features include:

* Patient profile registration with encrypted personal information.
* Healthcare provider registration with verification and specialization details.
* Medical record storage with various record types and severity/treatment statuses.
* Granular consent management allowing patients to control which providers can access their records.
* Emergency access overrides for critical situations.
* Audit trail for tracking record access with authorization status and access reasons.

## Features

### Patient Profiles

* Secure storage of encrypted personal information.
* Privacy levels ranging from public to fully private.
* Patient consent preferences and activation status.

### Healthcare Providers

* Registration controlled by system administrator.
* Provider types such as hospital, clinic, specialist, or pharmacy.
* Verification status and reputation scoring.

### Medical Records

* Various types of medical records (diagnosis, treatment, prescriptions, lab results, imaging).
* Severity and treatment status tracking.
* Access levels tailored to patient privacy preferences.

### Consent Management

* Patients explicitly grant and manage consent for providers.
* Consent includes expiry dates, access scope (read-only to full access), and emergency overrides.
* Specific records can be targeted for consent.

### Audit Trail

* Logs access events with details on accessor, type of access, reason, and authorization.
* Ensures transparency and accountability.

## Error Handling

The contract defines specific errors for unauthorized access, invalid data, missing patients/providers, and consent issues, ensuring robust validation and security.

## Usage

### Patient Registration

Patients can register themselves by providing encrypted personal data and setting their privacy level.

### Provider Registration

Only the system administrator can register healthcare providers with their credentials and specialization.

### Granting Consent

Patients grant consent to providers specifying access scope, duration, and emergency permissions.

### Query Functions

Read-only functions allow querying patient profiles, provider info, consent status, and provider verification.

## Constants

* `SYSTEM_ADMINISTRATOR` - The principal authorized to register healthcare providers.
* Error constants such as `ERR_ACCESS_UNAUTHORIZED`, `ERR_PATIENT_NOT_FOUND`, etc., for precise error management.

## Data Structures

* `patient-profiles` map storing patient details and preferences.
* `healthcare-providers` map for provider registration and verification.
* `medical-records` map for encrypted medical data and metadata.
* `consent-permissions` map for tracking patient-provider consent relationships.
* `audit-trail` map for access logging.

## Security and Privacy

* Patient data is stored encrypted off-chain with only hashes stored on-chain.
* Access controls enforced via consent permissions and provider verification.
* Emergency override mechanisms ensure critical access while maintaining auditability.

## Deployment & Administration

* The deploying principal is set as `SYSTEM_ADMINISTRATOR`.
* Only the administrator can add healthcare providers.
* Patients self-register and control their consent preferences.


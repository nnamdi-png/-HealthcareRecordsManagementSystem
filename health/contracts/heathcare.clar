;; Healthcare Records Management System
;; Secure and private medical record storage with patient consent controls

;; Constants
(define-constant SYSTEM_ADMINISTRATOR tx-sender)
(define-constant ERR_ACCESS_UNAUTHORIZED (err u500))
(define-constant ERR_PATIENT_NOT_FOUND (err u501))
(define-constant ERR_PROVIDER_NOT_AUTHORIZED (err u502))
(define-constant ERR_INVALID_RECORD_DATA (err u503))
(define-constant ERR_CONSENT_REQUIRED (err u504))
(define-constant ERR_RECORD_NOT_FOUND (err u505))
(define-constant ERR_INVALID_PROVIDER (err u506))

;; Data Variables
(define-data-var next-patient-id uint u1)
(define-data-var next-record-id uint u1)
(define-data-var next-provider-id uint u1)

;; Data Maps
(define-map patient-profiles
  { patient-id: uint }
  {
    patient-address: principal,
    encrypted-personal-info: (string-ascii 200),
    date-of-birth-hash: (string-ascii 64),
    emergency-contact-hash: (string-ascii 64),
    insurance-info-hash: (string-ascii 64),
    registration-date: uint,
    privacy-level: uint, ;; 1=public, 2=restricted, 3=private
    consent-preferences: uint,
    is-active: bool
  }
)

(define-map healthcare-providers
  { provider-id: uint }
  {
    provider-address: principal,
    provider-name: (string-ascii 120),
    provider-type: uint, ;; 1=hospital, 2=clinic, 3=specialist, 4=pharmacy
    license-number: (string-ascii 50),
    specialization: (string-ascii 100),
    verification-status: bool,
    registration-date: uint,
    patient-count: uint,
    reputation-score: uint
  }
)

(define-map medical-records
  { record-id: uint }
  {
    patient-id: uint,
    provider-id: uint,
    record-type: uint, ;; 1=diagnosis, 2=treatment, 3=prescription, 4=lab-result, 5=imaging
    encrypted-data-hash: (string-ascii 64),
    record-timestamp: uint,
    severity-level: uint, ;; 1-5 scale
    treatment-status: uint, ;; 1=ongoing, 2=completed, 3=discontinued
    follow-up-required: bool,
    access-level: uint ;; 1=patient-only, 2=authorized-providers, 3=emergency-access
  }
)

(define-map consent-permissions
  { patient-id: uint, provider-id: uint }
  {
    consent-granted: bool,
    consent-date: uint,
    consent-expiry: uint,
    access-scope: uint, ;; 1=read-only, 2=read-write, 3=full-access
    specific-records: (list 10 uint),
    emergency-override: bool
  }
)

(define-map audit-trail
  { record-id: uint, access-timestamp: uint }
  {
    accessor: principal,
    access-type: uint, ;; 1=read, 2=write, 3=share, 4=delete
    access-reason: (string-ascii 100),
    ip-hash: (string-ascii 64),
    is-authorized: bool
  }
)

;; Validation Functions
(define-private (is-valid-principal (addr principal))
  (not (is-eq addr 'SP000000000000000000002Q6VF78)))

(define-private (is-valid-hash (hash-str (string-ascii 64)))
  (and (> (len hash-str) u0) (<= (len hash-str) u64)))

(define-private (is-valid-specialization (spec (string-ascii 100)))
  (and (> (len spec) u0) (<= (len spec) u100)))

(define-private (is-valid-patient-id-input (patient-id uint))
  (and (> patient-id u0) (< patient-id (var-get next-patient-id))))

(define-private (is-valid-provider-id-input (provider-id uint))
  (and (> provider-id u0) (< provider-id (var-get next-provider-id))))

(define-private (is-valid-consent-expiry (expiry uint))
  (and (> expiry stacks-block-height) (<= expiry (+ stacks-block-height u525600)))) ;; Max 1 year

;; Patient Registration
(define-public (register-patient
  (patient-address principal)
  (encrypted-personal-info (string-ascii 200))
  (date-of-birth-hash (string-ascii 64))
  (emergency-contact-hash (string-ascii 64))
  (insurance-info-hash (string-ascii 64))
  (privacy-level uint))
  (let ((patient-id (var-get next-patient-id)))
    (asserts! (is-valid-principal patient-address) ERR_INVALID_RECORD_DATA)
    (asserts! (> (len encrypted-personal-info) u0) ERR_INVALID_RECORD_DATA)
    (asserts! (is-valid-hash date-of-birth-hash) ERR_INVALID_RECORD_DATA)
    (asserts! (is-valid-hash emergency-contact-hash) ERR_INVALID_RECORD_DATA)
    (asserts! (is-valid-hash insurance-info-hash) ERR_INVALID_RECORD_DATA)
    (asserts! (and (>= privacy-level u1) (<= privacy-level u3)) ERR_INVALID_RECORD_DATA)
    
    (map-set patient-profiles
      { patient-id: patient-id }
      {
        patient-address: patient-address,
        encrypted-personal-info: encrypted-personal-info,
        date-of-birth-hash: date-of-birth-hash,
        emergency-contact-hash: emergency-contact-hash,
        insurance-info-hash: insurance-info-hash,
        registration-date: stacks-block-height,
        privacy-level: privacy-level,
        consent-preferences: u1,
        is-active: true
      }
    )
    
    (var-set next-patient-id (+ patient-id u1))
    (ok patient-id)
  )
)

(define-public (register-healthcare-provider
  (provider-address principal)
  (provider-name (string-ascii 120))
  (provider-type uint)
  (license-number (string-ascii 50))
  (specialization (string-ascii 100)))
  (let ((provider-id (var-get next-provider-id)))
    (asserts! (is-eq tx-sender SYSTEM_ADMINISTRATOR) ERR_ACCESS_UNAUTHORIZED)
    (asserts! (is-valid-principal provider-address) ERR_INVALID_PROVIDER)
    (asserts! (> (len provider-name) u0) ERR_INVALID_PROVIDER)
    (asserts! (and (>= provider-type u1) (<= provider-type u4)) ERR_INVALID_PROVIDER)
    (asserts! (> (len license-number) u0) ERR_INVALID_PROVIDER)
    (asserts! (is-valid-specialization specialization) ERR_INVALID_PROVIDER)
    
    (map-set healthcare-providers
      { provider-id: provider-id }
      {
        provider-address: provider-address,
        provider-name: provider-name,
        provider-type: provider-type,
        license-number: license-number,
        specialization: specialization,
        verification-status: true,
        registration-date: stacks-block-height,
        patient-count: u0,
        reputation-score: u85
      }
    )
    
    (var-set next-provider-id (+ provider-id u1))
    (ok provider-id)
  )
)

;; Consent Management
(define-public (grant-provider-consent
  (patient-id uint)
  (provider-id uint)
  (consent-expiry uint)
  (access-scope uint)
  (emergency-override bool))
  (let ((validated-patient-id (begin 
                                (asserts! (is-valid-patient-id-input patient-id) ERR_PATIENT_NOT_FOUND)
                                patient-id))
        (validated-provider-id (begin 
                                 (asserts! (is-valid-provider-id-input provider-id) ERR_INVALID_PROVIDER)
                                 provider-id))
        (validated-consent-expiry (begin 
                                    (asserts! (is-valid-consent-expiry consent-expiry) ERR_INVALID_RECORD_DATA)
                                    consent-expiry))
        (patient (unwrap! (map-get? patient-profiles { patient-id: validated-patient-id }) ERR_PATIENT_NOT_FOUND)))
    (asserts! (is-eq tx-sender (get patient-address patient)) ERR_ACCESS_UNAUTHORIZED)
    (asserts! (is-some (map-get? healthcare-providers { provider-id: validated-provider-id })) ERR_INVALID_PROVIDER)
    (asserts! (and (>= access-scope u1) (<= access-scope u3)) ERR_INVALID_RECORD_DATA)
    
    (map-set consent-permissions
      { patient-id: validated-patient-id, provider-id: validated-provider-id }
      {
        consent-granted: true,
        consent-date: stacks-block-height,
        consent-expiry: validated-consent-expiry,
        access-scope: access-scope,
        specific-records: (list),
        emergency-override: emergency-override
      }
    )
    (ok true)
  )
)

;; Query Functions
(define-read-only (get-patient-profile (patient-id uint))
  (map-get? patient-profiles { patient-id: patient-id })
)

(define-read-only (get-provider-info (provider-id uint))
  (map-get? healthcare-providers { provider-id: provider-id })
)

(define-read-only (check-consent-status (patient-id uint) (provider-id uint))
  (match (map-get? consent-permissions { patient-id: patient-id, provider-id: provider-id })
    consent-data 
      (and 
        (get consent-granted consent-data)
        (> (get consent-expiry consent-data) stacks-block-height)
      )
    false
  )
)

(define-read-only (is-verified-provider (provider-id uint))
  (match (map-get? healthcare-providers { provider-id: provider-id })
    provider-data (get verification-status provider-data)
    false
  )
)

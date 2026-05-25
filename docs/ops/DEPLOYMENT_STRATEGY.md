# Deployment Strategy: Sovereignty vs. Cloud

## 1. Introduction
miTch is designed with strict **Privacy-by-Design** and **Data Sovereignty** principles. Choosing the right deployment model is critical to maintaining its 100% EUDI compliance status (CIR 2024/2981).

## 2. Model Comparison

| Feature | Docker (Sovereign / On-Prem) | Public Cloud (Managed) |
| :--- | :--- | :--- |
| **Data Sovereignty** | **High**: Complete control over data location and access. | **Medium**: Subject to US Cloud Act (if provider is US-based). |
| **Compliance** | Ideal for high-assurance (LoA High) certification. | Requires complex legal safeguards (SCCs, TIAs). |
| **Key Management** | Local HSM or secure vault integration. | Managed KMS (convenient but third-party access risk). |
| **Auditability** | Full control over logs and transparency layers. | Limited to what the provider exposes via APIs. |
| **Scalability** | Manual or via Kubernetes (Self-managed). | Automated (Serverless, Auto-scaling). |

## 3. The "miTch Sovereign" Model (Recommended)
To ensure that miTch remains compliant with European standards and avoids extra-territorial data access, the **Sovereign Docker Model** is the primary target for pilot rollouts.

### Deployment Stack
1.  **Docker Compose**: Orchestrates the microservices.
2.  **European Hosting**: Deploy on EU-based infrastructure (e.g., Hetzner, OVH, or private RZ).
3.  **TLS Termination**: Local proxy (Caddy/Nginx) ensuring no unencrypted traffic leaves the server.

## 4. Risks of Public Cloud (AWS/Azure/GCP)
- **CLOUDACT Exposure**: Potential conflict with GDPR Art. 48 and EUDI CIR 2024/2982.
- **Vendor Lock-in**: Hard dependencies on proprietary identity/crypto services.
- **Metadata Leaks**: Cloud providers often log metadata (IPs, timing) that miTch aims to minimize.

## 5. Conclusion
For the initial pilot phase, miTch will provide a **hardened Docker configuration**. This allows participants to run the stack on their own infrastructure, ensuring that the promise of "Alle sind miTch" (Privacy & Sovereignty) is kept at the infrastructure level.

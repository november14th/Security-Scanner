## Design Decisions

1. UI Design: A simple, intuitive interface for uploading files and entering URLs for scans. Designed for accessibility by both technical and non-technical users.

2. API Integrations:
- VirusTotal: Used for file and hash-based scans.
- urlscan.io: Used for URL scans.

3. File Security:
- Hash calculation performed locally before uploading files.
- Files are uploaded only with user consent.
- Temporary files are deleted immediately after upload.


4. Result Presentation: Results are shown in JSON format and can be enhanced for clarity using AI in future iterations.

## How to run in docker?


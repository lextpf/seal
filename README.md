<div align="center">

# seal
**AES-256-GCM credential manager with Qt6 GUI**

🛡️ [Features](#features) | 🚅 [Quick Start](#quick-start) | 📗 [Documentation](#documentation) | 🤝 [Contributing](./CONTRIBUTING.md)

![AES-256-GCM](https://img.shields.io/badge/AES--256-GCM-06B6D4.svg?style=flat&logo=data:image/svg+xml;base64,PHN2ZyBmaWxsPSIjZmZmZmZmIiBoZWlnaHQ9IjE2OHB4IiB3aWR0aD0iMTY4cHgiIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHZpZXdCb3g9Ii0yNS42IC0yNS42IDU2My4yMCA1NjMuMjAiIHhtbDpzcGFjZT0icHJlc2VydmUiPjxnIGlkPSJTVkdSZXBvX2JnQ2FycmllciIgc3Ryb2tlLXdpZHRoPSIwIj48L2c+PGcgaWQ9IlNWR1JlcG9fdHJhY2VyQ2FycmllciIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48L2c+PGcgaWQ9IlNWR1JlcG9faWNvbkNhcnJpZXIiPiA8Zz4gPGc+IDxnPiA8cGF0aCBkPSJNMjU2LDMyMGMtMTEuNzc2LDAtMjEuMzMzLDkuNTc5LTIxLjMzMywyMS4zMzNjMCwxMS43NTUsOS41NTcsMjEuMzMzLDIxLjMzMywyMS4zMzNzMjEuMzMzLTkuNTc5LDIxLjMzMy0yMS4zMzMgQzI3Ny4zMzMsMzI5LjU3OSwyNjcuNzc2LDMyMCwyNTYsMzIweiI+PC9wYXRoPiA8cGF0aCBkPSJNMzYyLjY2NywyMDguMzJWMTA2LjY2N0MzNjIuNjY3LDQ3Ljg1MSwzMTQuODE2LDAsMjU2LDBTMTQ5LjMzMyw0Ny44NTEsMTQ5LjMzMywxMDYuNjY3VjIwOC4zMiBjLTM4Ljk1NSwzMS4yOTYtNjQsNzkuMjUzLTY0LDEzMy4wMTNDODUuMzMzLDQzNS40MzUsMTYxLjg5OSw1MTIsMjU2LDUxMnMxNzAuNjY3LTc2LjU2NSwxNzAuNjY3LTE3MC42NjcgQzQyNi42NjcsMjg3LjU3Myw0MDEuNjIxLDIzOS42MTYsMzYyLjY2NywyMDguMzJ6IE0xOTIsMTA2LjY2N2MwLTM1LjI4NSwyOC43MTUtNjQsNjQtNjRzNjQsMjguNzE1LDY0LDY0djc2LjQ1OSBjLTIuMDkxLTAuODMyLTQuMjQ1LTEuNDUxLTYuMzU3LTIuMjE5Yy0yLjY4OC0wLjk4MS01LjMzMy0yLjAwNS04LjA4NS0yLjgzN2MtMi44NTktMC44NzUtNS44MDMtMS41MzYtOC43MjUtMi4yNjEgYy0yLjQzMi0wLjU5Ny00LjgyMS0xLjMwMS03LjI5Ni0xLjc5MmMtMy40NTYtMC42ODMtNi45NzYtMS4xMzEtMTAuNDc1LTEuNmMtMi4wNDgtMC4yNzctNC4wMzItMC42ODMtNi4xMDEtMC44OTYgYy01LjYxMS0wLjU1NS0xMS4yNjQtMC44NTMtMTYuOTYtMC44NTNzLTExLjM0OSwwLjI5OS0xNi45NiwwLjg1M2MtMi4wNjksMC4yMTMtNC4wNzUsMC42MTktNi4xMDEsMC44OTYgYy0zLjUyLDAuNDY5LTcuMDE5LDAuOTE3LTEwLjQ3NSwxLjZjLTIuNDc1LDAuNDkxLTQuODY0LDEuMTk1LTcuMzE3LDEuNzkyYy0yLjkwMSwwLjcyNS01Ljg0NSwxLjM4Ny04LjcwNCwyLjI2MSBjLTIuNzUyLDAuODMyLTUuNDE5LDEuODc3LTguMTA3LDIuODM3Yy0yLjExMiwwLjc2OC00LjI2NywxLjM4Ny02LjMzNiwyLjIxOVYxMDYuNjY3eiBNMzQxLjMzMywzNjIuNjY3aC0yNS4yNTkgYy02LjQ0MywxOC4wNjktMjAuNjcyLDMyLjI5OS0zOC43NDEsMzguNzQxdjI1LjI1OWMwLDExLjc3Ni05LjUzNiwyMS4zMzMtMjEuMzMzLDIxLjMzM3MtMjEuMzMzLTkuNTU3LTIxLjMzMy0yMS4zMzN2LTI1LjI1OSBjLTE4LjA2OS02LjQ0My0zMi4yOTktMjAuNjcyLTM4Ljc0MS0zOC43NDFoLTI1LjI1OWMtMTEuNzk3LDAtMjEuMzMzLTkuNTU3LTIxLjMzMy0yMS4zMzNjMC0xMS43NzYsOS41MzYtMjEuMzMzLDIxLjMzMy0yMS4zMzMgaDI1LjI1OWM2LjQ0My0xOC4wNjksMjAuNjcyLTMyLjI5OSwzOC43NDEtMzguNzQxVjI1NmMwLTExLjc3Niw5LjUzNi0yMS4zMzMsMjEuMzMzLTIxLjMzM3MyMS4zMzMsOS41NTcsMjEuMzMzLDIxLjMzM3YyNS4yNTkgYzE4LjA2OSw2LjQ0MywzMi4yOTksMjAuNjcyLDM4Ljc0MSwzOC43NDFoMjUuMjU5YzExLjc5NywwLDIxLjMzMyw5LjU1NywyMS4zMzMsMjEuMzMzIEMzNjIuNjY3LDM1My4xMDksMzUzLjEzMSwzNjIuNjY3LDM0MS4zMzMsMzYyLjY2N3oiPjwvcGF0aD4gPC9nPiA8L2c+IDwvZz4gPC9nPjwvc3ZnPg==)
![QR](https://img.shields.io/badge/Webcam-QR_Scan-3B82F6.svg?style=flat&logo=data:image/svg+xml;base64,PHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJJY29ucyIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgdmlld0JveD0iMCAwIDMyIDMyIiB4bWw6c3BhY2U9InByZXNlcnZlIiB3aWR0aD0iMTY4cHgiIGhlaWdodD0iMTY4cHgiIGZpbGw9IiNmZmZmZmYiPjxnIGlkPSJTVkdSZXBvX2JnQ2FycmllciIgc3Ryb2tlLXdpZHRoPSIwIj48L2c+PGcgaWQ9IlNWR1JlcG9fdHJhY2VyQ2FycmllciIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48L2c+PGcgaWQ9IlNWR1JlcG9faWNvbkNhcnJpZXIiPiA8c3R5bGUgdHlwZT0idGV4dC9jc3MiPiAuc3Qwe2ZpbGw6bm9uZTtzdHJva2U6I2ZmZmZmZjtzdHJva2Utd2lkdGg6MjtzdHJva2UtbGluZWNhcDpyb3VuZDtzdHJva2UtbGluZWpvaW46cm91bmQ7c3Ryb2tlLW1pdGVybGltaXQ6MTA7fSA8L3N0eWxlPiA8Zz4gPGNpcmNsZSBjeD0iMTYiIGN5PSIxNCIgcj0iMiI+PC9jaXJjbGU+IDxwYXRoIGQ9Ik0yMy40LDIzLjRjMi44LTIuMiw0LjYtNS42LDQuNi05LjRjMC02LjYtNS40LTEyLTEyLTEyUzQsNy40LDQsMTRjMCwzLjgsMS44LDcuMiw0LjYsOS40bC0xLjUsMS4zIGMtMC45LDAuOC0xLjIsMi4xLTAuOCwzLjNDNi44LDI5LjIsNy45LDMwLDkuMiwzMGgxMy43YzEuMiwwLDIuMy0wLjgsMi44LTEuOWMwLjUtMS4yLDAuMS0yLjUtMC44LTMuM0wyMy40LDIzLjR6IE0xNiwyMCBjLTMuMywwLTYtMi43LTYtNnMyLjctNiw2LTZzNiwyLjcsNiw2UzE5LjMsMjAsMTYsMjB6IE0yMi43LDkuN2MwLDAtMC4xLDAuMS0wLjIsMC4xYzAsMC0wLjEsMC4xLTAuMiwwLjFjLTAuMSwwLTAuMSwwLTAuMiwwLjEgYy0wLjEsMC0wLjEsMC0wLjIsMGMtMC4xLDAtMC4xLDAtMC4yLDBjLTAuMSwwLTAuMSwwLTAuMi0wLjFjLTAuMSwwLTAuMS0wLjEtMC4yLTAuMWMwLDAtMC4xLTAuMS0wLjEtMC4xYzAtMC4xLTAuMS0wLjEtMC4xLTAuMSBjMC0wLjEtMC4xLTAuMS0wLjEtMC4yYzAtMC4xLDAtMC4xLTAuMS0wLjJjMC0wLjEsMC0wLjEsMC0wLjJjMC0wLjEsMC0wLjEsMC0wLjJjMC0wLjEsMC0wLjEsMC4xLTAuMmMwLTAuMSwwLTAuMSwwLjEtMC4yIGMwLTAuMSwwLjEtMC4xLDAuMS0wLjFjMCwwLDAuMS0wLjEsMC4xLTAuMWMwLjEsMCwwLjEtMC4xLDAuMi0wLjFjMC4xLDAsMC4xLDAsMC4yLTAuMWMwLjMtMC4xLDAuNywwLDAuOSwwLjMgQzIyLjksOC41LDIzLDguNywyMyw5UzIyLjksOS41LDIyLjcsOS43eiI+PC9wYXRoPiA8L2c+IDwvZz48L3N2Zz4=)
![Browser Autofill](https://img.shields.io/badge/Browser-Autofill-F59E0B.svg?style=flat&logo=data:image/svg+xml;base64,PHN2ZyBoZWlnaHQ9IjIwMHB4IiB3aWR0aD0iMjAwcHgiIHZlcnNpb249IjEuMSIgaWQ9Il94MzJfIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2aWV3Qm94PSItMjUuNiAtMjUuNiA1NjMuMjAgNTYzLjIwIiB4bWw6c3BhY2U9InByZXNlcnZlIiBmaWxsPSIjZmZmZmZmIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMC4wMDUxMiI+PGcgaWQ9IlNWR1JlcG9fYmdDYXJyaWVyIiBzdHJva2Utd2lkdGg9IjAiPjwvZz48ZyBpZD0iU1ZHUmVwb190cmFjZXJDYXJyaWVyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHN0cm9rZT0iI0NDQ0NDQyIgc3Ryb2tlLXdpZHRoPSI0LjA5NiI+PC9nPjxnIGlkPSJTVkdSZXBvX2ljb25DYXJyaWVyIj4gPHN0eWxlIHR5cGU9InRleHQvY3NzIj4gLnN0MHtmaWxsOiNmZmZmZmY7fSA8L3N0eWxlPiA8Zz4gPHBhdGggY2xhc3M9InN0MCIgZD0iTTE4MC40LDIxMi40NzJjLTI0LjA5NCw0MS43MzEtOS43ODksOTUuMTA0LDMxLjk1LDExOS4yMTRjNDEuNzMxLDI0LjA4Niw5NS4xMTIsOS43ODksMTE5LjIxNC0zMS45NSBjMjQuMDk0LTQxLjczOSw5Ljc4OS05NS4xMTItMzEuOTUtMTE5LjIxNEMyNTcuODgyLDE1Ni40MjgsMjA0LjUwOSwxNzAuNzI1LDE4MC40LDIxMi40NzJ6Ij48L3BhdGg+IDxwYXRoIGNsYXNzPSJzdDAiIGQ9Ik0xODguMTEzLDM3My42NjRjLTIxLjM5OS0xMi4zNDktMzguMTIyLTI5LjcwOC00OS42MzYtNDkuNzE1bC0wLjA0OCwwLjAyNEwyOS45NDMsMTM2LjA4NyBDLTM0LjQ5LDI1Ny4yNzIsOC4xODcsNDA4LjYzNiwxMjcuOTgxLDQ3Ny44MDJjMjYuODkzLDE1LjUyMSw1NS40MzIsMjUuNjEyLDg0LjM0NSwzMC41OThsNjguNjk2LTExOC45NzYgQzI1MC4yMzMsMzk1LjIyOSwyMTcuMzA0LDM5MC41MywxODguMTEzLDM3My42NjR6Ij48L3BhdGg+IDxwYXRoIGNsYXNzPSJzdDAiIGQ9Ik0xMzguNDIyLDE4OC4yMjhjMjUuMDcyLTQzLjQzMyw3MC42OTItNjcuNzM0LDExNy41Ni02Ny44MTR2LTAuMDU1aDIxNy4wMzggYy0yMS40NzgtMzQuNDIzLTUxLjQ0OC02NC4yNDMtODkuMDM3LTg1Ljk1MkMyNzQuNDMtMjguODQyLDEzNy41OTUtMS44NjIsNTkuMzU3LDkyLjIzM2w2OC41OTIsMTE4Ljc5MyBDMTMwLjcwMSwyMDMuMjU2LDEzNC4xNDMsMTk1LjYyMywxMzguNDIyLDE4OC4yMjh6Ij48L3BhdGg+IDxwYXRoIGNsYXNzPSJzdDAiIGQ9Ik00OTYuMjIyLDE2Ny43NTlIMzU5LjAyOWMzNi4zOCw0Mi41MSw0NC4wNTMsMTA1LjA3NiwxNC41MTIsMTU2LjIxM0wyNjUuMDQ3LDUxMS45MTQgYzg1LjE1Ni0zLjEwOSwxNjYuODg1LTQ4LjU3LDIxMi42MzItMTI3LjgxQzUxNy4xOTEsMzE1LjY2Myw1MjEuNDg2LDIzNi41NTgsNDk2LjIyMiwxNjcuNzU5eiI+PC9wYXRoPiA8L2c+IDwvZz48L3N2Zz4=)
![No Telemetry](https://img.shields.io/badge/Telemetry-None-10B981.svg?style=flat&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTY4cHgiIGhlaWdodD0iMTY4cHgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBpZD0iU1ZHUmVwb19iZ0NhcnJpZXIiIHN0cm9rZS13aWR0aD0iMCI+PC9nPjxnIGlkPSJTVkdSZXBvX3RyYWNlckNhcnJpZXIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PC9nPjxnIGlkPSJTVkdSZXBvX2ljb25DYXJyaWVyIj4gPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzQyOV8xMTE1OCkiPiA8cGF0aCBkPSJNMTAuNzMwMiA1LjA3MzE5QzExLjE0NDggNS4wMjQ4NSAxMS41Njg0IDUgMTEuOTk5OSA1QzE2LjY2MzkgNSAyMC4zOTk4IDcuOTAyNjQgMjEuOTk5OSAxMkMyMS42MDUzIDEzLjAxMDQgMjEuMDgwOSAxMy45NDgyIDIwLjQ0NDYgMTQuNzg3N002LjUxOTU2IDYuNTE5NDRDNC40Nzk0OSA3Ljc2NDA2IDIuOTAxMDUgOS42OTI1OSAxLjk5OTk0IDEyQzMuNjAwMDggMTYuMDk3NCA3LjMzNTk3IDE5IDExLjk5OTkgMTlDMTQuMDM3NSAxOSAxNS44OTc5IDE4LjQ0NiAxNy40ODA1IDE3LjQ4MDRNOS44Nzg3MSA5Ljg3ODU5QzkuMzM1NzYgMTAuNDIxNSA4Ljk5OTk0IDExLjE3MTUgOC45OTk5NCAxMkM4Ljk5OTk0IDEzLjY1NjkgMTAuMzQzMSAxNSAxMS45OTk5IDE1QzEyLjgyODQgMTUgMTMuNTc4NSAxNC42NjQyIDE0LjEyMTQgMTQuMTIxMiIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIuNSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48L3BhdGg+IDxwYXRoIGQ9Ik00IDRMMjAgMjAiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCI+PC9wYXRoPiA8L2c+IDxkZWZzPiA8Y2xpcFBhdGggaWQ9ImNsaXAwXzQyOV8xMTE1OCI+IDxyZWN0IHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgZmlsbD0id2hpdGUiPjwvcmVjdD4gPC9jbGlwUGF0aD4gPC9kZWZzPiA8L2c+PC9zdmc+)
![Qt6](https://img.shields.io/badge/Qt6-GUI-8B5CF6.svg?style=flat&logo=qt&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.10%2B-c0392b?style=flat&logo=cmake&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-475569.svg?logo=data:image/svg+xml;base64,PHN2ZyBmaWxsPSIjZmZmZmZmIiB3aWR0aD0iMTY0cHgiIGhlaWdodD0iMTY0cHgiIHZpZXdCb3g9IjAgMCA1MTIuMDAgNTEyLjAwIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIwLjAwNTEyIj48ZyBpZD0iU1ZHUmVwb19iZ0NhcnJpZXIiIHN0cm9rZS13aWR0aD0iMCI+PC9nPjxnIGlkPSJTVkdSZXBvX3RyYWNlckNhcnJpZXIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIgc3Ryb2tlPSIjQ0NDQ0NDIiBzdHJva2Utd2lkdGg9IjMuMDcyIj48L2c+PGcgaWQ9IlNWR1JlcG9faWNvbkNhcnJpZXIiPjxwYXRoIGQ9Ik0yNTYgOEMxMTkuMDMzIDggOCAxMTkuMDMzIDggMjU2czExMS4wMzMgMjQ4IDI0OCAyNDggMjQ4LTExMS4wMzMgMjQ4LTI0OFMzOTIuOTY3IDggMjU2IDh6bTExNy4xMzQgMzQ2Ljc1M2MtMS41OTIgMS44NjctMzkuNzc2IDQ1LjczMS0xMDkuODUxIDQ1LjczMS04NC42OTIgMC0xNDQuNDg0LTYzLjI2LTE0NC40ODQtMTQ1LjU2NyAwLTgxLjMwMyA2Mi4wMDQtMTQzLjQwMSAxNDMuNzYyLTE0My40MDEgNjYuOTU3IDAgMTAxLjk2NSAzNy4zMTUgMTAzLjQyMiAzOC45MDRhMTIgMTIgMCAwIDEgMS4yMzggMTQuNjIzbC0yMi4zOCAzNC42NTVjLTQuMDQ5IDYuMjY3LTEyLjc3NCA3LjM1MS0xOC4yMzQgMi4yOTUtLjIzMy0uMjE0LTI2LjUyOS0yMy44OC02MS44OC0yMy44OC00Ni4xMTYgMC03My45MTYgMzMuNTc1LTczLjkxNiA3Ni4wODIgMCAzOS42MDIgMjUuNTE0IDc5LjY5MiA3NC4yNzcgNzkuNjkyIDM4LjY5NyAwIDY1LjI4LTI4LjMzOCA2NS41NDQtMjguNjI1IDUuMTMyLTUuNTY1IDE0LjA1OS01LjAzMyAxOC41MDggMS4wNTNsMjQuNTQ3IDMzLjU3MmExMi4wMDEgMTIuMDAxIDAgMCAxLS41NTMgMTQuODY2eiI+PC9wYXRoPjwvZz48L3N2Zz4=)
<br/>
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=lextpf_sage&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=lextpf_sage)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=lextpf_sage&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=lextpf_sage)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=lextpf_sage&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=lextpf_sage)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/16582af9eb8d478baee97e11e7d6b8bf)](https://app.codacy.com/gh/lextpf/seal/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
<br/>
[![build](https://github.com/lextpf/seal/actions/workflows/build.yml/badge.svg)](https://github.com/lextpf/seal/actions/workflows/build.yml)
[![tests](https://github.com/lextpf/seal/actions/workflows/test.yml/badge.svg)](https://github.com/lextpf/seal/actions/workflows/test.yml)
<br/>
![Sponsor](https://img.shields.io/static/v1?label=sponsor&message=%E2%9D%A4&color=ff69b4&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NDAgNjQwIj48IS0tIUZvbnQgQXdlc29tZSBQcm8gdjcuMi4wIGJ5IEBmb250YXdlc29tZSAtIGh0dHBzOi8vZm9udGF3ZXNvbWUuY29tIExpY2Vuc2UgLSBodHRwczovL2ZvbnRhd2Vzb21lLmNvbS9saWNlbnNlIChDb21tZXJjaWFsIExpY2Vuc2UpIENvcHlyaWdodCAyMDI2IEZvbnRpY29ucywgSW5jLi0tPjxwYXRoIG9wYWNpdHk9IjEiIGZpbGw9IiNmZjY5YjRmZiIgZD0iTTMyIDQ4MEwzMiA1NDRDMzIgNTYxLjcgNDYuMyA1NzYgNjQgNTc2TDM4NC41IDU3NkM0MTMuNSA1NzYgNDQxLjggNTY2LjcgNDY1LjIgNTQ5LjVMNTkxLjggNDU2LjJDNjA5LjYgNDQzLjEgNjEzLjQgNDE4LjEgNjAwLjMgNDAwLjNDNTg3LjIgMzgyLjUgNTYyLjIgMzc4LjcgNTQ0LjQgMzkxLjhMNDI0LjYgNDgwTDMxMiA0ODBDMjk4LjcgNDgwIDI4OCA0NjkuMyAyODggNDU2QzI4OCA0NDIuNyAyOTguNyA0MzIgMzEyIDQzMkwzODQgNDMyQzQwMS43IDQzMiA0MTYgNDE3LjcgNDE2IDQwMEM0MTYgMzgyLjMgNDAxLjcgMzY4IDM4NCAzNjhMMjMxLjggMzY4QzE5Ny45IDM2OCAxNjUuMyAzODEuNSAxNDEuMyA0MDUuNUw5OC43IDQ0OEw2NCA0NDhDNDYuMyA0NDggMzIgNDYyLjMgMzIgNDgweiIvPjxwYXRoIGZpbGw9InJnYmEoMjU1LCAyNTUsIDI1NSwgMS4wMCkiIGQ9Ik0yNTAuOSA2NEMyNzQuOSA2NCAyOTcuNSA3NS41IDMxMS42IDk1TDMyMCAxMDYuN0wzMjguNCA5NUMzNDIuNSA3NS41IDM2NS4xIDY0IDM4OS4xIDY0QzQzMC41IDY0IDQ2NCA5Ny41IDQ2NCAxMzguOUw0NjQgMTQxLjNDNDY0IDIwNS43IDM4MiAyNzQuNyAzNDEuOCAzMDQuNkMzMjguOCAzMTQuMyAzMTEuMyAzMTQuMyAyOTguMyAzMDQuNkMyNTguMSAyNzQuNiAxNzYgMjA1LjcgMTc2LjEgMTQxLjNMMTc2LjEgMTM4LjlDMTc2IDk3LjUgMjA5LjUgNjQgMjUwLjkgNjR6Ii8+PC9zdmc+)
</div>

**An encryption and credential manager** built with **C++23** and powered by *OpenSSL* **AES-256-GCM**. It pairs a *Qt6* interface, where credentials are stored **encrypted** and only *decrypted on demand*, with a *streaming CLI* that slots into **pipes** and **scripts**. seal can encrypt *individual files*, *entire directories*, or *inline text*, and fills credentials directly into applications or websites via its *auto-fill controller*. Under the hood, every secret sits in **hardened memory** - *locked pages*, *guard pages*, *canary sentinels* and the clipboard is **scrubbed automatically** if used.

> [!WARNING]
> seal is designed to protect sensitive information, but it is provided **as is** and used entirely at **your own risk**.<br>
> the author and contributors are **not liable for security incidents or other damages** arising from its use.

<div align="center">
<br>

<img src="PREVIEW.png" alt="Preview" width="525"/>

</div>

> [!IMPORTANT]
> **Windows 10/11 Only** - seal enforces Windows-specific security mitigations and will not build on other platforms.
>
> - For best protection, enable `SeLockMemoryPrivilege` via Group Policy (`gpedit.msc` -> Local Policies -> User Rights Assignment -> Lock pages in memory).
> - UI icons use [Font Awesome Pro 7.2](https://fontawesome.com/) SVGs, which are **not included** in this repository due to their commercial license. You must supply your own `assets/svgs/` from a valid Font Awesome Pro subscription.

```
/*  ============================================================================================  *
 *                                                            ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
 *                                                            ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
 *           ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
 *          :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
 *          +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
 *          +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
 *                 +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇
 *          #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
 *           ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
 *                                                            ⠀⠀⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 *
 *                                  << P A S S   M A N A G E R >>
 *
 *  ============================================================================================  */
```

```
seal/
|-- src/                                # C++23 core + CLI + Qt ViewModels (grouped by subsystem)
|   |-- main.cpp                        # Entry point; parses argv into a Mode, dispatches
|   |-- Cryptography.*                  # AES-256-GCM packets, scrypt KDF, hardening
|   |-- CryptoConfig.hpp                # KDF params, AAD framing, decode-cap constants
|   |-- CryptoGuards.hpp                # DPAPIGuard + EVP-context scoped RAII guards
|   |-- ScopedDpapiUnprotect.hpp        # RAII unprotect/reprotect window for a secret
|   |-- Vault.*                         # .seal load/save, rekey, credential crypto
|   |-- VaultRecord.hpp                 # Vault record + decrypted-credential structs
|   |-- FileOperations.*                # File / directory / stream encryption, batch I/O
|   |-- CredentialCsv.*                 # Chrome CSV import parser + seal CSV writer
|   |-- PasswordGen.*                   # Rejection-sampled random password generator
|   |-- Clipboard.*                     # Clipboard TTL-scrub + secure wipe helpers
|   |-- Utils.*                         # String, hex, base64, path, UTF-8/16 helpers
|   |-- SecureString.hpp                # Locked secure_string + RWGuard + triplet
|   |-- LockedAllocator.hpp             # VirtualLock allocator, guard pages + canary
|   |-- CredentialSession.*             # Sole owner of the master password (DPAPI-guarded)
|   |-- CredentialWorkspace.*           # Owns vault records + generation counter
|   |-- AsyncRunner.*                   # Thread-pool worker, GUI-thread marshalling
|   |-- CancellationToken.hpp           # Read-only cooperative cancellation flag
|   |-- AutoLockPolicy.hpp              # Pure idle auto-lock decision (unit-tested)
|   |-- AutoLockController.*            # Idle + WTS session-lock auto-lock trigger
|   |-- QmlMain.*                       # GUI composition root; wires 5 context props
|   |-- AppViewModel.*                  # Hub ViewModel: vault UI (QML: AppViewModel)
|   |-- CliPanelViewModel.*             # Embedded terminal-panel ViewModel (QML: Cli)
|   |-- BridgeViewModel.*               # Browser-companion enable/diagnose (QML: Bridge)
|   |-- TypeController.*                # Auto-fill surface over FillController (QML: Fill)
|   |-- WindowController.*              # Win32 window chrome/theme/motion (QML: WindowVM)
|   |-- VaultModel.*                    # Filtered, masked vault list model for QML
|   |-- IFillControl.hpp                # DI seam: arm / cancel the auto-fill engine
|   |-- IPasswordGate.hpp               # DI seam: master-password gate (FIFO defer)
|   |-- IUiFeedback.hpp                 # DI seam: status / loading / busy sink
|   |-- BrandIconResolver.*             # Platform label -> bundled brand-SVG path
|   |-- WindowChrome.*                  # Win32 frameless title bar + DWM theming
|   |-- NativeDialogs.*                 # Win32 file / folder picker dialogs
|   |-- FillController.*                # Global-hook fill state machine + typeSecret
|   |-- FusionDecider.*                 # Fuses probe results into a field verdict
|   |-- Probe.hpp                       # IProbe interface + ProbeContext / Result
|   |-- Win32StyleProbe.*               # Tier-1 ES_PASSWORD native edit-style probe
|   |-- UiaIsPasswordProbe.*            # Tier-1 MSAA / UIA IsPassword probe
|   |-- UiaMetadataProbe.*              # Tier-2 UIA metadata / form-context probe
|   |-- UiaCommon.*                     # Shared UIA tree-walk + hint-scan helpers
|   |-- ImeStateProbe.*                 # Tier-2 IME-absent weak-signal probe
|   |-- BrowserBridgeProbe.*            # Tier-1 browser-extension bridge probe
|   |-- StagingController.*             # Zero-gesture navigation-staged auto-fill
|   |-- AutoStagePolicy.hpp             # Pure site->record resolver + per-visit latches
|   |-- UrlBinding.hpp                  # Tiered host / registrable-name matching
|   |-- BrowserBridge.*                 # Per-run named-pipe server + peer hardening
|   |-- BridgeMessage.*                 # Bounded JSON parser for bridge messages
|   |-- ProcessPin.hpp                  # RAII process-handle pin vs PID recycling
|   |-- SignerUtils.hpp                 # WinVerifyTrust + SPKI-thumbprint checks
|   |-- QrCapture.*                     # Webcam QR decode into locked secure memory
|   |-- CameraSelector.*                # Enumerate, score, and open the best camera
|   |-- CliModes.*                      # gen/shred/hash/verify/list/get/... CLI modes
|   |-- CliDispatch.*                   # CLI file/dir/hex/base64 crypto dispatch
|   |-- CliHandler.*                    # CLI builtins + masked credential console
|   |-- Console.*                       # Masked console UI + password prompts
|   |-- ConsoleStyle.*                  # Semantic tone-coloured console output
|   |-- Diagnostics.*                   # logfmt field builders (joinFields / kv)
|   |-- Logging.*                       # Qt logging categories + stderr handler
|   +-- Version.hpp                     # Version-number macros + version string
|-- qml/                                # Qt6 QML UI (dumb views bound to the 5 ViewModels)
|   |-- Main.qml                        # Frameless app window: chrome, ambient, dialogs
|   |-- Theme.qml                       # Singleton theme: colors, HiDPI px, fonts, icons
|   |-- HeaderBar.qml                   # Title bar: logo, theme toggle, vault buttons
|   |-- SearchBar.qml                   # Debounced vault search + match count
|   |-- AccountsGrid.qml                # Credential-chip grid with empty states
|   |-- AccountChip.qml                 # Credential pill: brand icon or monogram
|   |-- AccountsToolbar.qml             # Grid header: account count + sort dropdown
|   |-- AccountDialog.qml               # Add / edit credential popup with validation
|   |-- PasswordDialog.qml              # Master-password prompt with QR-scan option
|   |-- RekeyDialog.qml                 # Master-password change dialog
|   |-- ConfirmDialog.qml               # Reusable confirm / info / error dialog
|   |-- BridgeSettings.qml              # Bridge status chips + auto-fill toggle
|   |-- CliPanel.qml                    # Embedded terminal: output + command input
|   |-- StatusFooter.qml                # Status bar: state, file, count, fill dot
|   |-- ActionBar.qml                   # Add / edit / delete / fill action buttons
|   |-- LoadingOverlay.qml              # Unseal sonar + success / break animation
|   |-- Ambient.qml                     # Singleton background-animation clock
|   |-- DialogBlobs.qml                 # Decorative blurred blobs behind dialogs
|   |-- RippleEffect.qml                # Masked button-press ripple animation
|   |-- TintedButton.qml                # Themed gradient button + icon + ripple
|   +-- SvgIcon.qml                     # DPI-aware recolorable SVG icon
|-- host/browser/                       # Native-messaging host -> seal-browser.exe
|   |-- main.cpp                        # stdio <-> named-pipe relay; no payload parsing
|   |-- BridgePipe.*                    # Locates + signer-verifies seal's bridge pipe
|   |-- MessageFraming.*                # 4-byte length framing over stdio + pipe
|   |-- HandleVerification.*            # Proves stdio pipes are from the browser
|   |-- LaunchOrigin.*                  # argv[1] native-messaging origin gate
|   |-- ExitLog.*                       # Best-effort exit diagnostics to file/stderr
|   +-- NtApi.hpp                       # Runtime-resolved ntdll for handle walk
|-- extensions/browser/                 # MV3 WebExtension companion (Chrome + Firefox)
|   |-- manifest.json                   # MV3 Chrome manifest: pinned key + host
|   |-- background.js                   # Service worker: connectNative, hashes path
|   |-- content.js                      # Classifies clicked field + reports nav
|   |-- firefox/manifest.json           # Firefox MV3 variant (gecko id, UUID)
|   +-- icons/                          # Extension icons (16 / 48 / 128 px)
|-- tests/                              # GoogleTest suites over the Qt-free cores
|   |-- test_*.cpp                      # crypto, vault, fusion, bridge, csv, ...
|   |-- test_helpers.hpp                # Shared fixtures: temp dirs + vault builders
|   +-- fixtures/                       # Sample Chrome CSVs for import tests
|-- cmake/                              # vcpkg overlay triplets (msvc143 release / static)
|-- scripts/                            # Doxide / MkDocs doc post-processing (Python)
|-- assets/                             # Bundled assets - NOT included; provide your own 
|-- CMakeLists.txt                      # seal + seal_browser targets + QML module
|-- CMakePresets.json                   # default / static / ci / compile-db presets
|-- vcpkg.json                          # Dependency manifest (Qt6, OpenSSL, OpenCV)
|-- build.bat                           # Full pipeline: format -> tidy -> build -> docs
|-- test.bat                            # Configure + build + run seal_tests
|-- doxide.yml                          # Doxide API-doc generator config
|-- mkdocs.yml                          # MkDocs documentation-site config
|-- sonar-project.properties            # SonarCloud analysis config
|-- qt.conf                             # Qt plugin search paths
|-- .clang-format / .clang-tidy         # Formatting + lint / naming rules
|-- .clangd                             # clangd LSP config (compile-db sidecar)
|-- .github/                            # CI workflows (build / test / sonar) + templates
|-- CONTRIBUTING.md                     # Contribution guide
|-- LICENSE.md                          # License
+-- README.md                           # Project overview (this file)
```

## Features

### Interface

seal ships with a **Qt6 QML** graphical manager and a **streaming CLI** for scripts and automation.

```mermaid
---
config:
  look: handDrawn
  theme: mc
  themeVariables:
    fontSize: 18px
  layout: elk
---
graph LR
    classDef gui fill:#134e3a,stroke:#10b981,color:#e2e8f0
    classDef cli fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
    classDef core fill:#2e1f5e,stroke:#8b5cf6,color:#e2e8f0

    subgraph GUI["🖥️ Qt6 GUI"]
        Vault["🔐 Vault Manager"]:::gui
        AutoFill["⌨️ Auto-Fill"]:::gui
        QR["📷 Webcam QR"]:::gui
    end

    subgraph CLI["⚡ Command Line"]
        Stream["📡 Stream Mode"]:::cli
        Interactive["💬 Interactive"]:::cli
        Import["📥 Batch Import"]:::cli
    end

    subgraph Core["🛡️ Crypto Engine"]
        AES["🔑 AES-256-GCM"]:::core
        Memory["🧱 Hardened Memory"]:::core
        Clipboard["📋 Clipboard Scrub"]:::core
    end

    GUI --> Core
    CLI --> Core
```

### Memory Protection

```mermaid
---
config:
  look: handDrawn
  theme: mc
  themeVariables:
    fontSize: 18px
  layout: elk
---
graph LR
    classDef lock fill:#7c2d12,stroke:#f97316,color:#fef3c7
    classDef guard fill:#4c1d95,stroke:#e879f9,color:#e2e8f0
    classDef wipe fill:#064e3b,stroke:#34d399,color:#e2e8f0
    classDef canary fill:#713f12,stroke:#facc15,color:#fef9c3

    V["🔒 VirtualLock"]:::lock
    G["🚧 Guard Pages"]:::guard
    S["🧹 SecureZeroMemory"]:::wipe
    C["🐤 0xD0 Canary"]:::canary

    V --- G --- S --- C
```

- 🔒 **VirtualLock** - Locks sensitive pages to prevent swapping to disk
- 🚧 **Guard Pages** - `PAGE_NOACCESS` regions flanking every allocation detect overflows
- 🧹 **Secure Wiping** - `SecureZeroMemory` scrubs data before deallocation
- 🐤 **Canary Protection** - 0xD0 sentinel at the tail of every buffer catches overruns
- 📋 **Clipboard Scrubbing** - Auto-wipes copied credentials after a configurable TTL
- 🔐 **DPAPI In-Memory Encryption** - Master password is wrapped with `CryptProtectMemory` while at rest
- 🔑 **Scrypt KDF** - Master password stretched with scrypt before AES key generation

### Anti-Tamper

- 🛡️ **Debugger Detection** - Three-layer check terminates on detection
- 💥 **Crash Dump Suppression** - Windows Error Reporting disabled
- 🧱 **Process Access DACL** - Restrictive SDDL blocks external processes from reading memory
- 🔥 **Heap Hardening** - `HeapEnableTerminationOnCorruption` terminates the process immediately on heap corruption
- 🔑 **SeLockMemoryPrivilege** - Requested at startup to support large-page VirtualLock
- ⌨️ **Keyboard Hook Detection** - Timing-based heuristic detects keylogger hooks before auto-type

### Vault System

Credentials are stored in `.seal` files using **on-demand decryption** - each record stays encrypted until the moment you need it.

|  Component | Description                                         |
|------------|-----------------------------------------------------|
|  Platform  | AES-256-GCM encrypted, displayed as search index    |
| Credential | `username:password` blob, decrypted only on access  |

### Additional Capabilities

- 📷 **Webcam QR** - Scan master password from a QR code via the built-in webcam capture
- ⌨️ **Auto-Fill** - Type credentials directly into target application fields
- 📁 **Batch Processing** - Encrypt/decrypt entire directories recursively
- 📡 **Stream Mode** - Pipe-friendly stdin/stdout encryption for scripting

## Technology Stack

| Component       | Technology              |
|-----------------|-------------------------|
| Language        | C++20                   |
| GUI Framework   | Qt6 (QML + Quick)       |
| Cryptography    | OpenSSL 3.x             |
| Build System    | CMake 3.20+             |
| Package Manager | vcpkg                   |
| Testing         | Google Test             |
| Documentation   | Doxide + MkDocs         |
| QR Capture      | OpenCV QRCodeDetector   |
| Platform        | Windows 10/11 (64-bit)  |

## Quick Start

### Prerequisites

- **Windows 10/11** (64-bit)
- **Visual Studio 2022** (MSVC v143, C++23)
- **CMake 3.20+**
- **vcpkg** with the toolchain at a known path
- **Python 3** (for documentation post-processing)
- **Font Awesome Pro 7.2** SVGs in `assets/svgs/` (not included, requires license)
- **doxide** + **mkdocs** (optional, for API docs generation)

### Building

```powershell
# 1. Clone the repository
git clone https://github.com/lextpf/seal.git
cd seal

# 2. Build (configure + compile + docs)
.\build.bat

# 3. Run
.\build\bin\Release\seal.exe
```

Output: `build/bin/Release/seal.exe`

## Architecture

```mermaid
---
config:
  look: handDrawn
  theme: mc
  themeVariables:
    fontSize: 18px
  layout: elk
---
graph LR
    classDef core fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
    classDef gui fill:#134e3a,stroke:#10b981,color:#e2e8f0
    classDef vault fill:#4a3520,stroke:#f59e0b,color:#e2e8f0
    classDef crypto fill:#2e1f5e,stroke:#8b5cf6,color:#e2e8f0

    Main["🚀 main.cpp"]:::core

    subgraph GUI["🖥️ GUI Layer"]
        Backend["⚙️ Backend"]:::gui
        QML["🎨 QML Views"]:::gui
        Fill["⌨️ FillController"]:::gui
    end

    subgraph Vault["🗄️ Vault Layer"]
        VaultModel["📋 VaultListModel"]:::vault
        VaultIO["💾 Vault I/O"]:::vault
    end

    subgraph Crypto["🔐 Crypto Layer"]
        Cryptography["🔑 Cryptography"]:::crypto
        FileOps["📁 FileOperations"]:::crypto
        Clipboard["📋 Clipboard"]:::crypto
    end

    Main --> GUI
    Main --> Vault
    GUI --> Vault
    Vault --> Crypto
    GUI --> Crypto
```

## Documentation

API documentation is generated via a three-stage pipeline:

```powershell
# 1. Generate markdown from C++ headers
doxide build

# 2. Post-process (strip noise, fix formatting, add icons)
python scripts/clean_docs.py

# 3. Build the documentation site
mkdocs build
```

The site is output to `site/` and can be served locally with `mkdocs serve`.

## Troubleshooting

|                  Problem | Solution                                                                |
|--------------------------|-------------------------------------------------------------------------|
| `SeLockMemoryPrivilege`  | Enable via `gpedit.msc` -> Local Policies -> User Rights Assignment     |
| Remote Desktop blocked   | Intended - seal refuses to run over RDP for security                    |
| vcpkg ninja crash        | Known issue with bundled ninja 1.13.2, retry or use system ninja        |
| Qt plugins not found     | Ensure `windeployqt` ran during build, check `qt.conf` paths            |

## Contributing

Contributions are welcome! Please read the [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. ~~Run tests and~~ ensure the build passes
5. Commit with descriptive messages
6. Push to your fork and open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.

## Acknowledgments

- [OpenSSL](https://www.openssl.org/) - Cryptographic primitives
- [Qt](https://www.qt.io/) - GUI framework
- [Google Test](https://github.com/google/googletest) - Testing framework
- [vcpkg](https://github.com/microsoft/vcpkg) - C++ package manager
- [Doxide](https://github.com/lawmurray/doxide) - API documentation generator
- [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) - Documentation theme
- [Font Awesome Pro 7.2](https://fontawesome.com/) - UI icons
- [Claude](https://claude.ai/) - AI coding assistant by Anthropic
- [Codex](https://openai.com/index/openai-codex/) - AI coding assistant by OpenAI

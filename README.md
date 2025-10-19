# PCAP Analyzer

A comprehensive network traffic analysis platform built with Go and React. This tool provides detailed analysis of PCAP files including asset discovery, OS fingerprinting, connection tracking, and more.

## Features

### Backend (Go)
- **PCAP Analysis Engine**: Uses gopacket library to decode and analyze network packets
- **Asset Discovery**: Identifies unique source IP addresses as network assets
- **Target Identification**: Categorizes destination IPs as public or local
- **TCP Connection Analysis**: Tracks TCP streams with detailed metrics:
  - Source/Destination IP and ports
  - Bytes sent/received
  - Connection duration
  - Service identification (HTTP, HTTPS, SSH, FTP, Torrent, etc.)
- **OS Fingerprinting**: Identifies operating systems using:
  - HTTP User-Agent strings
  - SSH banners
  - TCP window sizes
  - DHCP packets
- **UDP/ICMP Analysis**: Tracks non-TCP protocols (DNS, DHCP, NTP, ICMP)
- **Async Processing**: Background job processing with worker pool
- **Session-Based Authentication**: Secure user authentication with cookies
- **RESTful API**: Clean API design with proper error handling

### Frontend (React + Material-UI)
- **Login Page**: Secure authentication with demo account
- **Dashboard**: Upload PCAP files and view analysis history
- **Analysis Results**: Comprehensive view with multiple tabs:
  - Overview with summary cards
  - Assets table with OS information
  - Targets table with public/local classification
  - TCP connections with detailed metrics
  - Other connections (UDP, ICMP)
- **Real-time Updates**: Polling for analysis status
- **Clean Professional UI**: Material-UI components for modern look

## Tech Stack

### Backend
- Go 1.21+
- Gin Web Framework
- gopacket for PCAP analysis
- SQLite for data storage
- bcrypt for password hashing

### Frontend
- React 18
- Material-UI (MUI)
- React Router for navigation
- Axios for API calls

### DevOps
- Docker & Docker Compose
- Multi-stage builds for optimization
- Nginx for frontend serving

## Project Structure

```
pcap-analyzer/
├── backend/
│   ├── cmd/
│   │   └── server/
│   │       └── main.go           # Entry point
│   ├── internal/
│   │   ├── api/
│   │   │   ├── handlers/         # HTTP handlers
│   │   │   ├── middleware/       # Auth middleware
│   │   │   └── router.go         # Route definitions
│   │   ├── analyzer/
│   │   │   ├── pcap.go          # Core PCAP analysis
│   │   │   ├── tcp.go           # TCP tracking
│   │   │   ├── udp.go           # UDP/ICMP tracking
│   │   │   ├── fingerprint.go   # OS fingerprinting
│   │   │   └── worker.go        # Async job processing
│   │   ├── database/
│   │   │   ├── db.go            # Database initialization
│   │   │   ├── models.go        # Data models
│   │   │   └── queries.go       # Database queries
│   │   └── session/
│   │       └── session.go       # Session management
│   ├── uploads/                  # PCAP file storage
│   ├── data/                     # SQLite database
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Login.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Upload.jsx
│   │   │   └── AnalysisResults.jsx
│   │   ├── services/
│   │   │   └── api.js           # API client
│   │   └── App.js
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml
├── go.mod
└── README.md
```

## Installation & Setup

### Prerequisites
- Go 1.21 or higher
- Node.js 18 or higher
- libpcap development libraries
- Docker & Docker Compose (for containerized deployment)

### Local Development

#### Backend Setup

1. Install dependencies:
```bash
go mod download
```

2. Run the backend server:
```bash
go run backend/cmd/server/main.go
```

The server will start on `http://localhost:8080`

#### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The frontend will start on `http://localhost:3000`

### Docker Deployment

Build and run with Docker Compose:

```bash
docker-compose up --build
```

Services:
- Frontend: http://localhost:3000
- Backend: http://localhost:8080

## Usage

### Demo Account
- Username: `demo`
- Password: `demo`

### Workflow

1. **Login**: Access the application using the demo credentials
2. **Upload**: Upload a .pcap or .pcapng file through the dashboard
3. **Analysis**: The system processes the file asynchronously
4. **Results**: View comprehensive analysis results including:
   - Asset and target counts
   - Operating system detection
   - Connection details
   - Service identification

### API Endpoints

#### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/session` - Check session status

#### Analysis
- `POST /api/upload` - Upload PCAP file
- `GET /api/analysis/:id` - Get analysis results
- `GET /api/analyses` - List all analyses
- `DELETE /api/analysis/:id` - Delete analysis

## Database Schema

### Users
- id, username, password_hash, created_at

### Sessions
- session_id, user_id, expires_at

### Analyses
- id, user_id, filename, status, error_msg, created_at, completed_at

### Assets
- id, analysis_id, ip_address, os_type, os_confidence, mac_address

### Targets
- id, analysis_id, ip_address, label (public/local)

### TCP Connections
- id, analysis_id, src_ip, dst_ip, src_port, dst_port, bytes_sent, bytes_received, protocol, duration_ms, service, start_time, end_time

### Other Connections
- id, analysis_id, src_ip, dst_ip, src_port, dst_port, bytes_sent, bytes_received, protocol, duration_ms, service, start_time, end_time

## Features in Detail

### OS Fingerprinting
The system uses multiple techniques to identify operating systems:
- **HTTP User-Agent**: Analyzes user agent strings to detect Windows, Linux, macOS, Android, iOS
- **SSH Banners**: Identifies Linux distributions from SSH server banners
- **TCP Window Size**: Common window sizes help identify OS types
- **TTL Analysis**: Time-to-live values provide additional OS hints

### Service Identification
Services are identified based on port numbers:
- HTTP (80), HTTPS (443)
- SSH (22), FTP (21)
- DNS (53), DHCP (67/68)
- Torrent (6881-6889, 6969)
- And many more...

### Connection Tracking
- **TCP**: Full stream tracking with SYN/FIN/RST detection
- **UDP**: Flow-based tracking with service identification
- **ICMP**: Message tracking with timing information

## Security Considerations

- Passwords are hashed using bcrypt
- Session-based authentication with secure cookies
- File upload validation (only .pcap and .pcapng)
- User isolation (users can only access their own analyses)

## Performance

- Asynchronous job processing prevents UI blocking
- Worker pool handles multiple analyses concurrently
- SQLite with proper indexing for fast queries
- Efficient packet processing with gopacket

## Future Enhancements

- Real-time packet capture support
- More advanced OS fingerprinting techniques
- Machine learning for anomaly detection
- Export functionality (CSV, JSON, PDF)
- Advanced filtering and search
- Multi-user support with roles
- Dashboard analytics and visualizations

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the terms specified in the LICENSE file.

## Acknowledgments

- gopacket library for packet processing
- Material-UI for React components
- Gin web framework for Go

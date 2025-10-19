# Quick Start Guide

## Option 1: Docker (Recommended)

### Prerequisites
- Docker
- Docker Compose

### Steps

1. Clone the repository and navigate to the project directory:
```bash
cd pcap-analyzer
```

2. Build and start the containers:
```bash
docker-compose up --build
```

3. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8080

4. Login with demo credentials:
- Username: `demo`
- Password: `demo`

## Option 2: Local Development

### Prerequisites
- Go 1.21+
- Node.js 18+
- libpcap-dev (Linux) or WinPcap/Npcap (Windows)

### Backend Setup

1. Install Go dependencies:
```bash
go mod tidy
```

2. Start the backend server:
```bash
go run backend/cmd/server/main.go
```

Server starts on http://localhost:8080

### Frontend Setup

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

Frontend starts on http://localhost:3000

## Using the Application

### 1. Login
- Open http://localhost:3000
- Use credentials: `demo` / `demo`

### 2. Upload PCAP File
- Click "Choose File" on the dashboard
- Select a .pcap or .pcapng file
- Click "Upload and Analyze"

### 3. View Results
- Wait for analysis to complete (status updates automatically)
- View comprehensive results across multiple tabs:
  - **Assets**: Source IPs with OS detection
  - **Targets**: Destination IPs (public/local)
  - **TCP Connections**: Detailed connection information
  - **Other Connections**: UDP/ICMP traffic

### 4. Manage Analyses
- View all analyses in the dashboard table
- Click eye icon to view results
- Click delete icon to remove analysis

## Testing with Sample PCAP

If you don't have a PCAP file, you can:
1. Download sample PCAPs from https://wiki.wireshark.org/SampleCaptures
2. Use tcpdump to capture your own traffic:
   ```bash
   sudo tcpdump -i any -w sample.pcap -c 1000
   ```

## Troubleshooting

### Backend Issues

**Error: "libpcap not found"**
- Linux: `sudo apt-get install libpcap-dev`
- macOS: `brew install libpcap`
- Windows: Install Npcap from https://npcap.com/

**Database errors**
- Ensure `backend/data` directory exists
- Check file permissions

### Frontend Issues

**Cannot connect to backend**
- Verify backend is running on port 8080
- Check CORS settings in `backend/internal/api/router.go`

**Build fails**
- Clear node_modules: `rm -rf node_modules && npm install`
- Clear cache: `npm cache clean --force`

### Docker Issues

**Port already in use**
- Stop conflicting services
- Or modify ports in `docker-compose.yml`

**Build fails**
- Clean Docker cache: `docker system prune -a`
- Rebuild: `docker-compose up --build --force-recreate`

## Next Steps

1. Upload your own PCAP files for analysis
2. Explore the different tabs to understand network traffic
3. Use OS fingerprinting results to identify devices
4. Analyze connection patterns and services

## API Testing

You can test the API directly using curl:

```bash
# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"demo"}' \
  -c cookies.txt

# Upload PCAP
curl -X POST http://localhost:8080/api/upload \
  -H "Content-Type: multipart/form-data" \
  -F "file=@sample.pcap" \
  -b cookies.txt

# Get analysis results
curl http://localhost:8080/api/analysis/1 -b cookies.txt
```

## Support

For issues and questions, please refer to the main README.md or create an issue in the repository.

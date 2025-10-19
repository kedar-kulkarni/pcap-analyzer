import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  CircularProgress,
  Alert,
  Tabs,
  Tab,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
} from '@mui/material';
import { useParams } from 'react-router-dom';
import { getAnalysis } from '../services/api';

function TabPanel({ children, value, index }) {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

function AnalysisResults() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tabValue, setTabValue] = useState(0);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const result = await getAnalysis(id);
        setData(result);
        setLoading(false);

        // Poll for updates if analysis is not completed
        if (result.analysis && result.analysis.status !== 'completed' && result.analysis.status !== 'failed') {
          setTimeout(fetchData, 3000);
        }
      } catch (err) {
        setError(err.response?.data?.error || 'Failed to load analysis');
        setLoading(false);
      }
    };

    fetchData();
  }, [id]);

  if (loading && !data) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    );
  }

  if (!data) return null;

  // If analysis is still processing
  if (data.analysis && (data.analysis.status === 'pending' || data.analysis.status === 'processing')) {
    return (
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <CircularProgress sx={{ mb: 2 }} />
          <Typography variant="h6">
            Analysis in progress...
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Status: {data.analysis.status}
          </Typography>
        </Paper>
      </Container>
    );
  }

  // If analysis failed
  if (data.analysis && data.analysis.status === 'failed') {
    return (
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Alert severity="error">
          Analysis failed: {data.analysis.error_msg}
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        Analysis Results
      </Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        File: {data.analysis.filename}
      </Typography>

      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Assets
              </Typography>
              <Typography variant="h4">{data.asset_count}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Targets
              </Typography>
              <Typography variant="h4">{data.target_count}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Public IPs
              </Typography>
              <Typography variant="h4">{data.public_targets}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Local IPs
              </Typography>
              <Typography variant="h4">{data.local_targets}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Assets" />
          <Tab label="Targets" />
          <Tab label="TCP Connections" />
          <Tab label="Other Connections" />
        </Tabs>

        <TabPanel value={tabValue} index={0}>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell>Operating System</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>MAC Address</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.assets && data.assets.map((asset) => (
                  <TableRow key={asset.id}>
                    <TableCell>{asset.ip_address}</TableCell>
                    <TableCell>{asset.os_type}</TableCell>
                    <TableCell>{asset.os_confidence.toFixed(1)}%</TableCell>
                    <TableCell>{asset.mac_address || '-'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell>Type</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.targets && data.targets.map((target) => (
                  <TableRow key={target.id}>
                    <TableCell>{target.ip_address}</TableCell>
                    <TableCell>
                      <Chip
                        label={target.label}
                        color={target.label === 'public' ? 'primary' : 'default'}
                        size="small"
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Destination IP</TableCell>
                  <TableCell>Service</TableCell>
                  <TableCell>Bytes Sent</TableCell>
                  <TableCell>Bytes Received</TableCell>
                  <TableCell>Duration (ms)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.tcp_connections && data.tcp_connections.map((conn) => (
                  <TableRow key={conn.id}>
                    <TableCell>{conn.src_ip}:{conn.src_port}</TableCell>
                    <TableCell>{conn.dst_ip}:{conn.dst_port}</TableCell>
                    <TableCell>
                      <Chip label={conn.service} size="small" />
                    </TableCell>
                    <TableCell>{conn.bytes_sent.toLocaleString()}</TableCell>
                    <TableCell>{conn.bytes_received.toLocaleString()}</TableCell>
                    <TableCell>{conn.duration_ms.toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        <TabPanel value={tabValue} index={3}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Destination IP</TableCell>
                  <TableCell>Protocol</TableCell>
                  <TableCell>Service</TableCell>
                  <TableCell>Bytes Sent</TableCell>
                  <TableCell>Duration (ms)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.other_connections && data.other_connections.map((conn) => (
                  <TableRow key={conn.id}>
                    <TableCell>
                      {conn.src_ip}{conn.src_port ? `:${conn.src_port}` : ''}
                    </TableCell>
                    <TableCell>
                      {conn.dst_ip}{conn.dst_port ? `:${conn.dst_port}` : ''}
                    </TableCell>
                    <TableCell>{conn.protocol}</TableCell>
                    <TableCell>
                      <Chip label={conn.service} size="small" />
                    </TableCell>
                    <TableCell>{conn.bytes_sent.toLocaleString()}</TableCell>
                    <TableCell>{conn.duration_ms.toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>
      </Paper>
    </Container>
  );
}

export default AnalysisResults;

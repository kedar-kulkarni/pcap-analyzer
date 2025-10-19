import React, { useState, useEffect } from 'react';
import {
  Container,
  Grid,
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
} from '@mui/material';
import { Delete, Visibility } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { logout, getAnalyses, deleteAnalysis } from '../services/api';
import Upload from './Upload';

function Dashboard() {
  const [analyses, setAnalyses] = useState([]);
  const navigate = useNavigate();

  const fetchAnalyses = async () => {
    try {
      const result = await getAnalyses();
      setAnalyses(result.analyses || []);
    } catch (err) {
      console.error('Failed to fetch analyses:', err);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, []);

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/login');
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this analysis?')) {
      try {
        await deleteAnalysis(id);
        fetchAnalyses();
      } catch (err) {
        console.error('Failed to delete analysis:', err);
      }
    }
  };

  const handleView = (id) => {
    navigate(`/analysis/${id}`);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'failed':
        return 'error';
      case 'processing':
        return 'info';
      default:
        return 'default';
    }
  };

  return (
    <Box>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            PCAP Analyzer
          </Typography>
          <Button color="inherit" onClick={handleLogout}>
            Logout
          </Button>
        </Toolbar>
      </AppBar>

      <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Upload />
          </Grid>

          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Recent Analyses
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>File</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Created</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {analyses.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} align="center">
                          No analyses yet. Upload a PCAP file to get started.
                        </TableCell>
                      </TableRow>
                    ) : (
                      analyses.map((analysis) => (
                        <TableRow key={analysis.id}>
                          <TableCell>{analysis.filename}</TableCell>
                          <TableCell>
                            <Chip
                              label={analysis.status}
                              color={getStatusColor(analysis.status)}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            {new Date(analysis.created_at).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            <IconButton
                              size="small"
                              onClick={() => handleView(analysis.id)}
                              disabled={analysis.status === 'pending'}
                            >
                              <Visibility />
                            </IconButton>
                            <IconButton
                              size="small"
                              onClick={() => handleDelete(analysis.id)}
                            >
                              <Delete />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
}

export default Dashboard;

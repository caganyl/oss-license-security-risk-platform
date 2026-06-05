import express from 'express';
import dotenv from 'dotenv';
import pool from './lib/db';
import createUserRouter from './routes/userRoutes';
import createSbomRouter from './routes/sbomRoutes';
import createReportRouter from './routes/reportRoutes';
import createWorkflowRouter from './routes/workflowRoutes';

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

app.use(express.json());

// Mock Auth Middleware to populate req.user for easy testing/demo
app.use((req, res, next) => {
  req.user = {
    id: '00000000-0000-0000-0000-000000000000', // Mock Admin UUID or similar
    email: 'admin@company.com',
    displayName: 'Admin User',
    roles: ['admin'],
    sessionId: 'mock-session-id'
  };
  next();
});

// Mount routes
app.use('/api/users', createUserRouter(pool));
app.use('/api', createSbomRouter(pool));
app.use('/api', createReportRouter(pool));
app.use('/api/findings', createWorkflowRouter(pool));

// Base health route
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected' });
  } catch (err: any) {
    res.status(500).json({ status: 'unhealthy', error: err.message });
  }
});

app.listen(port, () => {
  console.log(`OSS License & Security Risk Platform Backend listening on port ${port}`);
});

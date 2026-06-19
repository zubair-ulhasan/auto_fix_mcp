// In-memory seed data for the Fastn-resembling sandbox app.
// Mirrors PerfAI's real Fastn engagement account structure: Account 1 has
// the full 6-role roster, Account 2 only has an Owner (used to prove
// cross-tenant/BOLA access against Account 1's resources).

const orgs = [
  { id: 'org_1', name: 'Account 1', plan: 'enterprise', billingEmail: 'billing@account1.test' },
  { id: 'org_2', name: 'Account 2', plan: 'starter', billingEmail: 'billing@account2.test' },
];

const users = [
  { id: 'u1', email: 'owner@account1.test', password: 'owner123', role: 'owner', orgId: 'org_1' },
  { id: 'u2', email: 'operator@account1.test', password: 'operator123', role: 'operator', orgId: 'org_1' },
  { id: 'u3', email: 'developer@account1.test', password: 'developer123', role: 'developer', orgId: 'org_1' },
  { id: 'u4', email: 'viewer@account1.test', password: 'viewer123', role: 'viewer', orgId: 'org_1' },
  { id: 'u5', email: 'enduser@account1.test', password: 'enduser123', role: 'end_user', orgId: 'org_1' },
  { id: 'u6', email: 'customer@account1.test', password: 'customer123', role: 'customer', orgId: 'org_1' },
  { id: 'u7', email: 'owner@account2.test', password: 'owner123', role: 'owner', orgId: 'org_2' },
];

const apiKeys = {
  org_1: [
    { id: 'key_1', name: 'CI pipeline key', secret: 'sk_live_account1_8f2a1c9d4e' },
    { id: 'key_2', name: 'Analytics export key', secret: 'sk_live_account1_7b3e0a55f1' },
  ],
  org_2: [
    { id: 'key_3', name: 'Default key', secret: 'sk_live_account2_1d9f4b22ae' },
  ],
};

const connectors = {
  org_1: [
    { id: 'conn_1', name: 'Salesforce', type: 'crm', secret: 'conn_secret_sf_4a91' },
    { id: 'conn_2', name: 'Slack', type: 'messaging', secret: 'conn_secret_slack_1c77' },
  ],
  org_2: [{ id: 'conn_3', name: 'HubSpot', type: 'crm', secret: 'conn_secret_hs_9e02' }],
};

const workflows = {
  org_1: [
    { id: 'wf_1', name: 'Lead sync', status: 'active' },
    { id: 'wf_2', name: 'Nightly export', status: 'paused' },
  ],
  org_2: [{ id: 'wf_3', name: 'Ticket sync', status: 'active' }],
};

const auditLog = {
  org_1: [
    { id: 'log_1', actor: 'owner@account1.test', action: 'connector.created', timestamp: '2026-06-10T09:12:00Z' },
    { id: 'log_2', actor: 'developer@account1.test', action: 'workflow.deployed', timestamp: '2026-06-12T14:03:00Z' },
  ],
  org_2: [{ id: 'log_3', actor: 'owner@account2.test', action: 'org.created', timestamp: '2026-06-01T08:00:00Z' }],
};

const usage = {
  org_1: { apiCalls: 184320, storageGB: 42.7, billingPlan: 'enterprise' },
  org_2: { apiCalls: 1280, storageGB: 1.1, billingPlan: 'starter' },
};

const hubSettings = {
  org_1: { webhookUrl: 'https://hooks.account1.test/incoming', notifyEmail: 'alerts@account1.test' },
  org_2: { webhookUrl: 'https://hooks.account2.test/incoming', notifyEmail: 'alerts@account2.test' },
};

module.exports = { orgs, users, apiKeys, connectors, workflows, auditLog, usage, hubSettings };

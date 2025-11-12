-- ============================================================================
-- PostgreSQL Authentication & RBAC Database Schema
-- Simple role-based access with module-level permissions
-- Supports: Contract Intelligence, Spend Intelligence, Material Intelligence
-- ============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table - stores user account information
-- Each user has ONE role
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    department VARCHAR(100),
    role_id UUID,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    created_by VARCHAR(255),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL
);

-- Roles table - defines available roles in the system
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Note: Each user has ONE role stored directly in users table
-- No separate user_roles table needed

-- Modules table - intelligence modules in the system
CREATE TABLE IF NOT EXISTS modules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    module_code VARCHAR(100) UNIQUE NOT NULL,
    module_name VARCHAR(255) NOT NULL,
    description TEXT,
    icon VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    display_order INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Role_Module_Access table - defines which modules each role can access
-- If a role has access to a module, they can perform ALL operations (no edit/view distinction)
CREATE TABLE IF NOT EXISTS role_module_access (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL,
    module_id UUID NOT NULL,
    has_access BOOLEAN DEFAULT true,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE,
    UNIQUE(role_id, module_id)
);

-- Sessions table - tracks active user sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Audit log table - tracks authentication and access events
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255),
    event_type VARCHAR(100) NOT NULL,
    event_description TEXT,
    module_code VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (module_code) REFERENCES modules(module_code) ON DELETE SET NULL
);

-- ============================================================================
-- INDEXES for performance
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_role_module_access_role ON role_module_access(role_id);
CREATE INDEX IF NOT EXISTS idx_role_module_access_module ON role_module_access(module_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_module ON audit_log(module_code);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- ============================================================================
-- DEFAULT DATA - Insert roles and modules
-- ============================================================================

-- Insert Intelligence Modules
INSERT INTO modules (module_code, module_name, description, icon, display_order) VALUES
    ('CONTRACT_INTELLIGENCE', 'Contract Intelligence', 'AI-powered contract analysis and management', 'contract', 1),
    ('SPEND_INTELLIGENCE', 'Spend Intelligence', 'Spending analysis and optimization', 'analytics', 2),
    ('MATERIAL_INTELLIGENCE', 'Material Intelligence', 'Material and supply chain intelligence', 'inventory', 3)
ON CONFLICT (module_code) DO NOTHING;

-- Insert System Roles
INSERT INTO roles (role_name, description, is_active) VALUES
    ('admin', 'Administrator - Full system access', true),
    ('contract_analyst', 'Contract Analyst - Access to Contract Intelligence', true),
    ('spend_analyst', 'Spend Analyst - Access to Spend Intelligence', true),
    ('material_analyst', 'Material Analyst - Access to Material Intelligence', true),
    ('manager', 'Manager - Access to all modules', true),
    ('viewer', 'Viewer - Read-only access to all modules', true)
ON CONFLICT (role_name) DO NOTHING;

-- Map Module Access to Roles (using UUIDs)
-- If a role has access (has_access=true), they can do EVERYTHING in that module

-- Admin - Full access to all modules
INSERT INTO role_module_access (role_id, module_id, has_access)
SELECT r.id, m.id, true
FROM roles r
CROSS JOIN modules m
WHERE r.role_name = 'admin'
ON CONFLICT (role_id, module_id) DO NOTHING;

-- Contract Analyst - Only Contract Intelligence
INSERT INTO role_module_access (role_id, module_id, has_access)
SELECT r.id, m.id, true
FROM roles r
CROSS JOIN modules m
WHERE r.role_name = 'contract_analyst' AND m.module_code = 'CONTRACT_INTELLIGENCE'
ON CONFLICT (role_id, module_id) DO NOTHING;

-- Spend Analyst - Only Spend Intelligence
INSERT INTO role_module_access (role_id, module_id, has_access)
SELECT r.id, m.id, true
FROM roles r
CROSS JOIN modules m
WHERE r.role_name = 'spend_analyst' AND m.module_code = 'SPEND_INTELLIGENCE'
ON CONFLICT (role_id, module_id) DO NOTHING;

-- Material Analyst - Only Material Intelligence
INSERT INTO role_module_access (role_id, module_id, has_access)
SELECT r.id, m.id, true
FROM roles r
CROSS JOIN modules m
WHERE r.role_name = 'material_analyst' AND m.module_code = 'MATERIAL_INTELLIGENCE'
ON CONFLICT (role_id, module_id) DO NOTHING;

-- Manager - Full access to all modules
INSERT INTO role_module_access (role_id, module_id, has_access)
SELECT r.id, m.id, true
FROM roles r
CROSS JOIN modules m
WHERE r.role_name = 'manager'
ON CONFLICT (role_id, module_id) DO NOTHING;

-- Viewer - Access to all modules
INSERT INTO role_module_access (role_id, module_id, has_access)
SELECT r.id, m.id, true
FROM roles r
CROSS JOIN modules m
WHERE r.role_name = 'viewer'
ON CONFLICT (role_id, module_id) DO NOTHING;

-- ============================================================================
-- SAMPLE DATA for testing (password: password123 - bcrypt hashed)
-- ============================================================================

-- Insert Sample Users (each user has ONE role using role_id UUID)
INSERT INTO users (user_id, email, password_hash, first_name, last_name, department, role_id, status)
SELECT
    'user-admin-001',
    'admin@example.com',
    '$2b$12$YQ8nuzZFznjO8shINs2gy.tmQYJ0WQ0ZwVYxwgpYf4rMcK39SXph6',
    'System',
    'Administrator',
    'IT',
    r.id,
    'active'
FROM roles r WHERE r.role_name = 'admin'
ON CONFLICT (email) DO NOTHING;

INSERT INTO users (user_id, email, password_hash, first_name, last_name, department, role_id, status)
SELECT
    'user-contract-001',
    'contract@example.com',
    '$2b$12$YQ8nuzZFznjO8shINs2gy.tmQYJ0WQ0ZwVYxwgpYf4rMcK39SXph6',
    'John',
    'Contract',
    'Legal',
    r.id,
    'active'
FROM roles r WHERE r.role_name = 'contract_analyst'
ON CONFLICT (email) DO NOTHING;

INSERT INTO users (user_id, email, password_hash, first_name, last_name, department, role_id, status)
SELECT
    'user-spend-001',
    'spend@example.com',
    '$2b$12$YQ8nuzZFznjO8shINs2gy.tmQYJ0WQ0ZwVYxwgpYf4rMcK39SXph6',
    'Sarah',
    'Spend',
    'Finance',
    r.id,
    'active'
FROM roles r WHERE r.role_name = 'spend_analyst'
ON CONFLICT (email) DO NOTHING;

INSERT INTO users (user_id, email, password_hash, first_name, last_name, department, role_id, status)
SELECT
    'user-material-001',
    'material@example.com',
    '$2b$12$YQ8nuzZFznjO8shINs2gy.tmQYJ0WQ0ZwVYxwgpYf4rMcK39SXph6',
    'Mike',
    'Material',
    'Procurement',
    r.id,
    'active'
FROM roles r WHERE r.role_name = 'material_analyst'
ON CONFLICT (email) DO NOTHING;

INSERT INTO users (user_id, email, password_hash, first_name, last_name, department, role_id, status)
SELECT
    'user-manager-001',
    'manager@example.com',
    '$2b$12$YQ8nuzZFznjO8shINs2gy.tmQYJ0WQ0ZwVYxwgpYf4rMcK39SXph6',
    'Lisa',
    'Manager',
    'Procurement',
    r.id,
    'active'
FROM roles r WHERE r.role_name = 'manager'
ON CONFLICT (email) DO NOTHING;

INSERT INTO users (user_id, email, password_hash, first_name, last_name, department, role_id, status)
SELECT
    'user-viewer-001',
    'viewer@example.com',
    '$2b$12$YQ8nuzZFznjO8shINs2gy.tmQYJ0WQ0ZwVYxwgpYf4rMcK39SXph6',
    'View',
    'Only',
    'Business',
    r.id,
    'active'
FROM roles r WHERE r.role_name = 'viewer'
ON CONFLICT (email) DO NOTHING;

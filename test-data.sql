INSERT INTO users (id, email, password, name, surname) VALUES 
('641f7b5c-e236-4bd8-a8d6-4f207c880f91', 'helphobb@gmail.com', '$2a$10$AKxdgGg8aa3pAWr.cMKbCO55rXv9k6xL.2tvBmc8Tg5VR.TUhSVUa', 'Test', 'User'),
('11111111-2222-3333-4444-555555555555', 'sender@example.com', '$2a$10$AKxdgGg8aa3pAWr.cMKbCO55rXv9k6xL.2tvBmc8Tg5VR.TUhSVUa', 'Test', 'Receiver');

INSERT INTO wallets (id, user_id, balance, currency, status, created_at) VALUES 
(gen_random_uuid(), '641f7b5c-e236-4bd8-a8d6-4f207c880f91', 100, 'USD', 'active', NOW()),
(gen_random_uuid(), '641f7b5c-e236-4bd8-a8d6-4f207c880f91', 10000, 'NGN', 'active', NOW()),
(gen_random_uuid(), '641f7b5c-e236-4bd8-a8d6-4f207c880f91', 100, 'EUR', 'active', NOW()),
(gen_random_uuid(), '641f7b5c-e236-4bd8-a8d6-4f207c880f91', 100, 'CNY', 'active', NOW()),
(gen_random_uuid(), '11111111-2222-3333-4444-555555555555', 50, 'USD', 'active', NOW()),
(gen_random_uuid(), '11111111-2222-3333-4444-555555555555', 5000, 'NGN', 'active', NOW()),
(gen_random_uuid(), '11111111-2222-3333-4444-555555555555', 50, 'EUR', 'active', NOW()),
(gen_random_uuid(), '11111111-2222-3333-4444-555555555555', 50, 'CNY', 'active', NOW());
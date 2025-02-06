-- Crear Base de datos
CREATE DATABASE phishguard; 

-- Conecciòn a la Base de datos;
\c phishguard;

-- Table: public.users
CREATE TABLE IF NOT EXISTS public.users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    role VARCHAR(20) NOT NULL
);

-- Table: public.urls
CREATE TABLE IF NOT EXISTS public.urls (
    url_id SERIAL PRIMARY KEY,
    url VARCHAR(500) NOT NULL,
    verification_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    status VARCHAR(50) NOT NULL,
    risk_percentage NUMERIC(5, 2) NOT NULL,
    user_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    CONSTRAINT fk_urls_users FOREIGN KEY (user_id) REFERENCES public.users (user_id) ON DELETE CASCADE
);

-- Table: public.providers
CREATE TABLE IF NOT EXISTS public.providers (
    provider_id SERIAL PRIMARY KEY,
    provider_name VARCHAR(100) NOT NULL,
    provider_email VARCHAR(100) UNIQUE NOT NULL,
    url_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_providers_urls FOREIGN KEY (url_id) REFERENCES public.urls (url_id) ON DELETE CASCADE
);

-- Table: public.analysis
CREATE TABLE IF NOT EXISTS public.analysis (
    analysis_id SERIAL PRIMARY KEY,
    url_id INT NOT NULL,
    traceroute_result TEXT NOT NULL,
    methodology VARCHAR(100) NOT NULL,
    risk_percentage NUMERIC(5, 2) NOT NULL,
    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    CONSTRAINT fk_analysis_urls FOREIGN KEY (url_id) REFERENCES public.urls (url_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_users_email ON public.users (email);
CREATE INDEX idx_urls_status ON public.urls (status);
CREATE INDEX idx_analysis_date ON public.analysis (analysis_date);

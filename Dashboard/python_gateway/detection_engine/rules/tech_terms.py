"""Technology names that the NER model mistakes for people, places or companies.

Developer prompts are the gateway's main traffic, and spaCy's small model
tags capitalised product names as entities ("Django" -> PERSON, "Flask"
-> LOCATION, "Kafka vs Redis vs Postgres" -> PERSON). Sanitizing them
turns "a Django app" into "a [PERSON_NAME_1] app" and ruins the prompt.
An NER hit that contains one of these words is dropped. Regex rules
(emails, keys, Sri Lankan names, addresses) are unaffected.
"""

from __future__ import annotations

TECH_TERMS = frozenset({
    # languages and runtimes
    "python", "java", "javascript", "typescript", "kotlin", "swift", "golang", "rust", "ruby", "php",
    "perl", "scala", "haskell", "elixir", "erlang", "clojure", "dart", "lua", "bash", "powershell",
    "node", "nodejs", "deno", "bun", "dotnet", "net", "c#", "c++", "sql", "graphql", "html", "css",
    # frameworks and libraries
    "django", "flask", "fastapi", "pydantic", "spring", "boot", "laravel", "symfony", "rails", "express",
    "nestjs", "nextjs", "next", "nuxt", "react", "angular", "vue", "svelte", "jquery", "bootstrap",
    "tailwind", "redux", "vite", "webpack", "babel", "electron", "flutter", "xamarin", "hibernate",
    "pandas", "numpy", "scipy", "matplotlib", "seaborn", "sklearn", "tensorflow", "keras", "pytorch",
    "torch", "spacy", "presidio", "langchain", "llamaindex", "hugging", "transformers", "celery",
    "sqlalchemy", "prisma", "sequelize", "mongoose", "junit", "pytest", "jest", "mocha", "selenium",
    "playwright", "cypress",
    # data stores and messaging
    "postgres", "postgresql", "mysql", "mariadb", "sqlite", "oracle", "mssql", "mongodb", "mongo",
    "redis", "cassandra", "elasticsearch", "opensearch", "kibana", "logstash", "kafka", "rabbitmq",
    "zookeeper", "neo4j", "dynamodb", "firestore", "firebase", "supabase", "snowflake", "bigquery",
    "clickhouse", "influxdb", "prometheus", "grafana",
    # infrastructure and tooling
    "docker", "kubernetes", "k8s", "helm", "terraform", "ansible", "puppet", "chef", "vagrant",
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence", "git", "nginx", "apache",
    "tomcat", "linux", "ubuntu", "debian", "centos", "windows", "macos", "android", "ios",
    "aws", "azure", "gcp", "heroku", "vercel", "netlify", "cloudflare", "openshift", "istio",
    "ollama", "qwen", "llama", "mistral", "gemini", "copilot", "chatgpt", "openai", "anthropic",
    "claude", "jupyter", "vscode", "intellij", "eclipse", "postman", "swagger", "openapi",
    "excel", "powerbi", "tableau", "sharepoint", "outlook", "teams", "slack", "zoom",
})

CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`timestamp` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`actor` text NOT NULL,
	`department` text DEFAULT 'Unknown' NOT NULL,
	`service` text NOT NULL,
	`action` text NOT NULL,
	`status` text NOT NULL,
	`risk` text NOT NULL,
	`risk_score` integer DEFAULT 0 NOT NULL,
	`finding` text NOT NULL,
	`category` text NOT NULL,
	`policy_rule` text DEFAULT 'Unassigned' NOT NULL,
	`masked_output` text NOT NULL,
	`prompt_hash` text DEFAULT '' NOT NULL,
	`source` text DEFAULT 'gateway' NOT NULL,
	`ip_address` text DEFAULT '' NOT NULL,
	`user_agent` text DEFAULT '' NOT NULL
);

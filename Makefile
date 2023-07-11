all: rules_metadata_install

rules_metadata.json:
	python3 .github/rules_metadata.py -o rules_metadata.json ../falco_rules/default_policies_new.yaml ../falco_rules/rules_files/awscloudtrail.yaml/10/content ../falco_rules/rules_files/azure_platformlogs.yaml/8/content ../falco_rules/rules_files/falco_rules.yaml/13/content ../falco_rules/rules_files/k8s_audit_rules.yaml/8/content ../falco_rules/rules_files/gcp_auditlog.yaml/8/content ../falco_rules/rules_files/okta_rules.yaml/11/content ../falco_rules/rules_files/github_rules.yaml/10/content

rules_metadata_install: rules_metadata.json
	mv rules_metadata.json metadata/rules_metadata.json


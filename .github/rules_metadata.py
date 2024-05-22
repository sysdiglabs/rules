#!/usr/bin/env python3

import getopt
import json
import logging
import os
import re
import requests
import sys
import tempfile

try:
        from ruamel.yaml import YAML
except ModuleNotFoundError:
        print('This requires ruamel.yaml to be installed.  Run:  sudo pip3 install ruamel.yaml')
        sys.exit(2)


def findinPolicy(rule, policydoc):
	severity = 0
	disabled = True
	polname = ''

	for policy in policydoc:
		if not policy['ruleNames']:
			continue

		if rule in policy['ruleNames']:
			polname = policy['name']
			severity = policy['severity']
			if policy['enabled'] is True:
				disabled = False
			break

	if not polname:
		log.debug('Policy not found for: %s' % rule)

	return (severity, disabled, polname)


def fetchOSSRules():
	'''Fetch and load OSS rules for comparisons.'''

	ossuris = [
		'https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml',
		'https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml',
		'https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/okta/rules/okta_rules.yaml',
		'https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/github/rules/github.yaml'
	]

	tmp = tempfile.TemporaryFile()

	yaml = YAML(typ='rt')
	yaml.width = 4096
	yaml.indent(mapping=2, sequence=2, offset=0)
	yaml.preserve_quotes = True

	for ossuri in ossuris:
		try:
			doc = yaml.load(requests.get(ossuri).content)
			yaml.dump(doc, tmp)
		except Exception as e:
			log.warning('YAML format error in %s:\n%s' % (filen, e))

	tmp.seek(0)

	ossrules = yaml.load(tmp)

	return ossrules


def parseRulesYAML(rulesdoc, policydoc):
	ruleset = []

	ossrules = fetchOSSRules()

	for obj in rulesdoc:
		rule = {}

		objtype = list(obj.keys())[0]

		if objtype not in ('rule'):
			continue

		obj[objtype] = re.sub(r'(?:^[\x22\x27]|[\x22\x27]$)', '', obj[objtype])

		# rule name
		rule['rule'] = obj[objtype]

		rule['desc'] = re.sub(r'(?s)[\x0d\x0a]*$', '', obj['desc'])

		rule['priority'] = obj['priority']

		(severity, rule['disabled'], policy) = findinPolicy(rule['rule'], policydoc)
		if not rule['disabled']:
			rule['severity'] = severity
			rule['policy'] = policy

		if 'source' not in obj:
			obj['source'] = 'falco'

		rule['source'] = obj['source']

		rule['tags'] = []
		if 'tags' in obj:
			for tag in sorted(obj['tags']):
				tag = re.sub(r'_', ' ', tag)
				if tag[0] == tag[0].lower():
					tag = tag.title()
				rule['tags'].append(tag)

		# OSS rule comparison check
		rule['oss_rule'] = False

		for ossrule in ossrules:
			if list(ossrule)[0] != 'rule':
				continue

			if ossrule['rule'] != rule['rule']:
				continue

			rule['oss_rule'] = True

			if ossrule['condition'] == obj['condition']:
				rule['updated_oss_condition'] = False
			else:
				rule['updated_oss_condition'] = True

		if 'exceptions' in obj:
			rule['has_exceptions'] = True
		else:
			rule['has_exceptions'] = False

		ruleset.append(rule)

	ruleset.sort(key=lambda x: x['rule'])

	return ruleset


def outputJSON(data, outfile='rules_metadata.json'):
	log.info('Writing out JSON %s' % outfile)

	with open(outfile, 'w') as f:
		json.dump(data, f, sort_keys=True, indent=2)

	return


class DummyLogger():
	def exception(self, msg=""):
		return

	def error(self, msg=""):
		return

	def warning(self, msg=""):
		return

	def info(self, msg=""):
		return

	def debug(sefl, msg=""):
		return

loggers = {}
log = DummyLogger()

def getLogger(name, loglevel=logging.INFO, console=True, logfile=None, syslog=None):
	global loggers
	global log

	if name in loggers:
		return loggers[name]

	# create logger
	logger = logging.getLogger(name)
	logger.setLevel(loglevel)

	formatter = logging.Formatter('[%(levelname)s %(asctime)s] %(name)s: %(message)s', '%H:%M:%S')

	if syslog:
		if isinstance(syslog, str):
			syslog = syslog.split(':')

		ch = logging.SysLogHandler(address=(syslog[0], syslog[1]))
		ch.setLevel(loglevel)
		ch.setFormatter(formatter)
		logger.addHandler(ch)

	if logfile:
		ch = logging.FileHandler(logfile)
		ch.setLevel(loglevel)
		ch.setFormatter(formatter)
		logger.addHandler(ch)

	if console:
		ch = logging.StreamHandler()
		ch.setLevel(loglevel)
		ch.setFormatter(formatter)
		logger.addHandler(ch)

	if not loggers:
		log = logger

	loggers[name] = logger
	return logger


def usage():
	tab=' ' * 4
	print('%s [options] <policy file> <rules directory>' % sys.argv[0])
	print('%s-d: show debugging messages' % tab)
	print('%s-h: this message' % tab)
	print('%s-q: Quiet, only error messages.' % tab)
	print('%s-o <filename>: Output JSON to filename.' % tab)
	return


def main():
	''' The main event '''
	try:
		optlist, targetList = getopt.getopt(sys.argv[1:], 'dho:q', [ 'debug', 'help', 'outfile', 'quiet' ])
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	loglevel = logging.INFO
	outfile = 'rules_metadata.json'

	for opt in optlist:
		if opt[0] in ('-h', '--help'):
			usage()
			sys.exit(0)
		elif opt[0] in ('-d', '--debug'):
			loglevel = logging.DEBUG
		elif opt[0] in ('-q', '--quiet'):
			loglevel = logging.ERROR
		elif opt[0] in ('-o', '--outfile'):
			outfile = opt[1]

	log = getLogger('Rules_Metadata', loglevel=loglevel)

	yaml = YAML(typ='rt')
	yaml.width = 4096
	yaml.indent(mapping=2, sequence=2, offset=0)
	yaml.preserve_quotes = True

	try:
		policydoc = yaml.load(open(targetList[0], 'r'))
		rulefiles = targetList[1:]
	except Exception as e:
		print('Error: %s' % e)
		usage()
		sys.exit(1)


	ruleset = []

	tmp = tempfile.TemporaryFile()

	for filen in rulefiles:
		try:
			doc = yaml.load(open(filen, 'r'))
			yaml.dump(doc, tmp)
		except Exception as e:
			log.warning('YAML format error in %s:\n%s' % (filen, e))

	tmp.seek(0)

	rulesyaml = yaml.load(tmp)

	ruleset = parseRulesYAML(rulesyaml, policydoc)
	log.debug('len %s' % len(ruleset))

	outputJSON(ruleset, outfile)

	return


if __name__ == '__main__': main()

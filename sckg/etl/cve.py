import json

from sckg.etl.generic import Generic

class CVE(Generic):

  def __init__(self, config):
    super().__init__(config)

  def extract(self, regime, parsable_document):
    lines = []
    with open(parsable_document, 'r') as f:
      lines = f.readlines()
    regime_list = []
    for line in lines:
      regime_list.append(json.loads(line))
    return regime_list

  def transform(self, regime, regime_list):
    regime_name = regime['description']
    cve_date = regime['meta']['bq_nvd_date']

    stmts = []
    stmts.append(self.create_regime(regime_name))

    for entry in regime_list:
      published_date = entry['publishedDate']
      last_modified_date = entry['lastModifiedDate']
      impact = entry['impact'].get('baseMetricV3', 'not specified')
      if impact != 'not specified':
        cvss_severity = impact['cvssV3']['baseSeverity']
        cvss_score = impact['cvssV3']['baseScore']
      else:
        cvss_severity = 'not specified'
        cvss_score = 'not specified'
      cve = entry['cve']
      cve_id = cve['CVE_data_meta']['ID']
      cve_assigner = cve['CVE_data_meta'].get('ASSIGNER', 'none')
      cwe_list = []
      for pdata in cve['problemtype']['problemtype_data']:
        if len(pdata['description']) == 0:
          cwe_value = 'none'
        else:
          cwe_value = pdata['description'][0]['value']
          cwe_list.append(cwe_value.replace('CWE-', ''))
      cve_description = ''
      for ddata in cve['description']['description_data']:
        cve_description = cve_description + ddata['value']

      stmts.append(self.create_vulnerability(
          properties={
              'published_date': published_date,
              'last_modified_date': last_modified_date,
              'cvss_severity': cvss_severity,
              'cvss_score': cvss_score,
              'cve_id': cve_id,
              'name': cve_id,
              'assigner': cve_assigner,
              'description': cve_description.replace('\\', '\\\\').replace("\'", "\\'")
          }
      ))

      for weakness in cwe_list:
        stmts.append(self.map_control_orphan(
            lhs_type='vulnerability',
            rhs_type='weakness',
            lhs={
                'name': cve_id
            },
            rhs={
                'name': weakness
            },
            relationship='REFERSTO',
            properties={
                'CVE_data_version': entry['configurations']['CVE_data_version']
            }
        ))

    return stmts
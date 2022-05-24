import itertools

from collections import OrderedDict

import xmltodict

from sckg.etl.generic import Generic

class CWE(Generic):

  def __init__(self, config):
    super().__init__(config)

  def extract(self, regime, parsable_document):
    with open(parsable_document, 'r') as f:
      source_dict = xmltodict.parse(f.read())
    return source_dict

  def transform(self, regime, regime_dict):
    regime_name = regime['description']
    cwe_version = regime['meta']['cwe_version']

    stmts = []
    r = {}
    r['weaknesses'] = regime_dict['Weakness_Catalog']['Weaknesses']['Weakness']
    r['categories'] = regime_dict['Weakness_Catalog']['Categories']['Category']
    r['views'] = regime_dict['Weakness_Catalog']['Views']['View']
    r['external_references'] = regime_dict['Weakness_Catalog']['External_References']['External_Reference']

    stmts.append(self.create_regime(regime_name))
    stmts.append(self.create_regime_family(regime_name,
                                           properties={'name': 'Weaknesses', 'cwe_meta_version': cwe_version}))
    stmts.append(self.create_regime_family(regime_name,
                                           properties={'name': 'Categories', 'cwe_meta_version': cwe_version}))
    stmts.append(self.create_regime_family(regime_name,
                                           properties={'name': 'Views', 'cwe_meta_version': cwe_version}))
    stmts.append(self.create_regime_family(regime_name,
                                           properties={'name': 'External References', 'cwe_meta_version': cwe_version}))
    stmts.append(self.create_regime_family(regime_name,
                                           properties={'name': 'Stakeholders', 'cwe_meta_version': cwe_version}))
    stmts.append(self.create_regime_family(regime_name,
                                           properties={'name': 'Platforms', 'cwe_meta_version': cwe_version}))

    for category in r['categories']:
      stmts.append(self.create_geneirc_control(regime_name,
                                               'family',
                                               'Categories',
                                               properties={
                                                   'category_id': category['@ID'],
                                                   'name': category['@Name'],
                                                   'status': category['@Status'],
                                                   'summary': category['Summary'],
                                                   'cwe_meta_version': regime['meta']['cwe_version']
                                               }))

    for reference in r['external_references']:
      stmts.append(self.create_geneirc_control(regime_name,
                                               'family',
                                               'External References',
                                               properties={
                                                   'reference_id': reference['@Reference_ID'],
                                                   'author': str(reference.get('Author', 'not specified')),
                                                   'publisher': reference.get('Publisher', 'not specified'),
                                                   'edition': reference.get('Edition', 'not specified'),
                                                   'name': reference['Title'],
                                                   'publication_year': reference.get('Publication_Year', 'not specified'),
                                                   'publication_month': reference.get('Publication_Month','not specified'),
                                                   'publication_day': reference.get('Publication_Day','not specified'),
                                                   'url': reference.get('URL', 'not specified'),
                                                   'cwe_meta_version': regime['meta']['cwe_version']
                                               }))

    # build initial dict of weakness
    weaknesses = {}
    for weakness in r['weaknesses']:
      weaknesses[weakness['@ID']] = weakness

    # create CWE controls, which will be deliberately orphaned
    for weakness_id in weaknesses.keys():
      weakness = weaknesses[weakness_id]
      if isinstance(weakness.get('Extended_Description'), OrderedDict):
        extended_description = str(itertools.chain.from_iterable(weakness['Extended_Description'].values())).replace('\'', '"').replace('\\', '\\\\')
      else:
        extended_description = weakness.get('Extended_Description', 'not specified').replace('\'', '"').replace('\\', '\\\\')
      # stmts.append(self.create_control_orphan(properties={
      stmts.append(self.create_weakness(properties={
          'name': weakness_id,
          'cwe_meta_version': regime['meta']['cwe_version'],
          'cwe_version': regime_dict['Weakness_Catalog']['@Version'],
          'id': weakness['@ID'],
          'cwe_name': weakness['@Name'].replace('\'', '"').replace('\\', '\\\\'),
          'abstraction': weakness.get('@Abstraction', 'not specified'),
          'structure': weakness.get('@Structure', 'not specified'),
          'status': weakness.get('@Status', 'not specified'),
          'description': weakness.get('Description', 'not specified').replace('\'', '"').replace('\\', '\\\\'),
          'extended_description': extended_description,
          'likelihood_of_exploit': weakness.get('Likelihood_Of_Exploit', 'not specified')
      }))

    # helper function to map controls
    def map_weakness(cwe_id, version, this_weakness):
      return self.map_control_orphan(
              lhs_type='weakness',
              rhs_type='weakness',
              lhs={
                  'name': cwe_id,
                  'cwe_meta_version': version
              },
              rhs={
                  'name': this_weakness['@CWE_ID'],
                  'cwe_meta_version': version
              },
              relationship=str(this_weakness['@Nature']).upper(),
              properties={
                  'nature': this_weakness.get('@Nature', 'not specified'),
                  'view_id': this_weakness.get('@View_ID', 'not specified'),
                  'ordinal': this_weakness.get('@Ordinal', 'not specified')
              }
          )

    # now add relationships

    # first handle weakness hierarchy
    for weakness_id in weaknesses.keys():
      weakness = weaknesses[weakness_id]
      if weakness.get('Related_Weaknesses'):
        related_weakness = weakness['Related_Weaknesses']['Related_Weakness']

        if isinstance(related_weakness, OrderedDict):
          # If there's just one related weakness, this object will be an
          # OrderedDict
          stmts.append(map_weakness(weakness_id, cwe_version, related_weakness))

        if isinstance(related_weakness, list):
          # There might be more than one related weakness, in which case this
          # will be a list
          for related in related_weakness:
            stmts.append(map_weakness(weakness_id, cwe_version, related))

    # add top level weaknesses to the Weaknesses baseline
    stmts.append("""MATCH (n:weakness) WHERE NOT (n)-[:CHILDOF]->() 
WITH n 
MATCH (r:regime {name: 'CWE'})-[:HAS]->(f:family {name: 'Weaknesses'})
WITH n, r, f
MERGE (f)-[:HAS]->(n);""")

    # now add references
    for weakness_id in weaknesses.keys():
      weakness = weaknesses[weakness_id]
      if weakness.get('References'):
        if isinstance(weakness['References']['Reference'], list):
          for reference in weakness['References']['Reference']:
            stmts.append(self.map_control_orphan(
                lhs_type='weakness',
                rhs_type='control',
                lhs={
                    'name': weakness_id,
                    'cwe_meta_version': '4.1'
                },
                rhs={
                    'reference_id': reference['@External_Reference_ID'],
                    'cwe_meta_version': '4.1'
                },
                relationship='REFERSTO',
                properties={
                    'section': reference.get('@Section', 'not specified').replace('\'', '\\\'')
                }
            ))
        else:
          reference = weakness['References']['Reference']
          stmts.append(self.map_control_orphan(
              lhs_type='weakness',
              rhs_type='control',
              lhs={
                  'name': weakness_id,
                  'cwe_meta_version': '4.1'
              },
              rhs={
                  'reference_id': reference['@External_Reference_ID'],
                  'cwe_meta_version': '4.1'
              },
              relationship='REFERSTO',
              properties={
                  'section': reference.get('@Section', 'not specified').replace('\'', '\\\'')
              }
          ))
#
#       # todo: handle ordanalities
#
#       # add platform mappings
#       def create_platform_control(platform, entry):
#         if entry.get('@Class') and not entry.get('@Name'):
#           platform_name = entry.get('@Class')
#         else:
#           platform_name = entry.get('@Name')
#         stmts.append(self.create_geneirc_control('CWE',
#                                                  'control',
#                                                  platform,
#                                                  properties={
#                                                      'name': platform_name,
#                                                  }))
#         debug_stmt2 = self.create_geneirc_control('CWE',
#                                                  'control',
#                                                  platform,
#                                                  properties={
#                                                      'name': platform_name,
#                                                  })
#         pause = True
#         return platform_name
#
#       for weakness_id in weaknesses.keys():
#         weakness = weaknesses[weakness_id]
#         if weakness.get('Applicable_Platforms'):
#           for platform in weakness['Applicable_Platforms'].keys():
#             stmts.append(self.create_geneirc_control('CWE',
#                                                      'family',
#                                                      'Platforms',
#                                                      properties={
#                                                          'name': platform,
#                                                          'cwe_platform': 'true'
#                                                      }))
#             debug_stmt = self.create_geneirc_control('CWE',
#                                                      'family',
#                                                      'Platforms',
#                                                      properties={
#                                                          'name': platform,
#                                                          'cwe_platform': 'true'
#                                                      })
#             pause = True
#
#             if isinstance(weakness['Applicable_Platforms'][platform], list):
#               for platform_entry in weakness['Applicable_Platforms'][platform]:
#                 control_platform_name = create_platform_control(platform, platform_entry)
#                 stmts.append(self.map_control_orphan(
#                     lhs={
#                         'name': control_platform_name,
#                         'cve_meta_version': cwe_version,
#                         'cwe_platform': 'true'
#                     },
#                     rhs={
#                         'name': weakness_id,
#                         'cve_meta_version': cwe_version
#                     },
#                     relationship='HAS',
#                     properties={}
#                 ))
#             if isinstance(weakness['Applicable_Platforms'][platform], OrderedDict):
#               control_platform_name = create_platform_control(platform, weakness['Applicable_Platforms'][platform])
#               stmts.append(self.map_control_orphan(
#                   lhs={
#                       'name': control_platform_name,
#                       'cve_meta_version': cwe_version,
#                       'cwe_platform': 'true'
#                   },
#                   rhs={
#                       'name': weakness_id,
#                       'cve_meta_version': cwe_version
#                   },
#                   relationship='HAS',
#                   properties={}
#               ))

    return stmts

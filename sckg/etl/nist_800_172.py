from sckg.etl.generic import Generic

class NIST800172(Generic):

  def __init__(self, config):
    super().__init__(config)

  def transform(self, regime, regime_list):
    regime_name = regime['description']

    # create the regime
    stmts = []
    stmts.append(self.create_regime(regime_name))

    # create all the control families
    families = {}
    for control in regime_list:
      families[control['family']] = 1
    for family in families.keys():
      stmts.append(self.create_regime_family(regime_name,
                                             properties={
                                                 'name': family
                                             }))
    # create the controls
    for control in regime_list:
      family = control['family']
      name = control.get('identifier', 'none')
      identifier = control.get('identifier', 'none')
      sort_as = control['sort_as']
      requirement = control.get('enhanced_security_requirements', 'none')
      discussion = control.get('discussion', 'none')
      protection_strategy = control.get('protection_strategy', 'none')
      adversary_effects = control.get('adversary_effects_see_sp_800_160_volume_2', 'none')

      stmts.append(self.create_geneirc_control(regime_name,
                                               'family',
                                               family,
                                               properties={
                                                   'name': name,
                                                   'identifier': identifier,
                                                   'sort_as': sort_as,
                                                   'requirement': requirement,
                                                   'discussion': discussion,
                                                   'protection_strategy': protection_strategy,
                                                   'adversary_effects': adversary_effects
                                               }))
      # associate 800-172 controls with identifiers from 800-171r2
      identifier_171 = identifier.replace('e', '')
      stmts.append(self.create_control_control_map(names={
          'by_regime': True,
          'mapping_regime': regime_name,
          'mapped_regime': 'NIST 800-171r2',
          'mapping_control': identifier,
          'mapped_control': identifier_171,
          'relationship': 'ENHANCES'
      },
      properties={
          'derived': True
      }))

    return stmts

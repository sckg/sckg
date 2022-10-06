from sckg.etl.generic import Generic

class NIST800171(Generic):

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
      derived_requirement = control['basicderived_security_requirement']
      name = control['identifier']
      identifier = control['identifier']
      sort_as = control['sort_as']
      requirement = control['_security_requirement']
      discussion = control['discussion']
      stmts.append(self.create_geneirc_control(regime_name,
                                               'family',
                                               family,
                                               properties={
                                                   'derived_requirement': derived_requirement,
                                                   'name': name,
                                                   'identifier': identifier,
                                                   'sort_as': sort_as,
                                                   'requirement': requirement,
                                                   'discussion': discussion
                                               }))
    return stmts

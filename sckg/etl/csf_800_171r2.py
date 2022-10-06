from sckg.etl.generic import Generic

class CSF800171(Generic):

  def __init__(self, config):
    super().__init__(config)

  def transform(self, regime, regime_list):
    stmts = []
    for control in regime_list:
      subcategory = control['_csf_subcategory']
      identifier = control.get('cui_requirement', None)
      if identifier:
        stmts.append(self.create_control_control_map(
            names={
              'by_regime': True,
              'csf_800_171': True,
              'mapping_regime': 'NIST 800-171r2',
              'mapped_regime': 'NIST CSF',
              'mapping_control': identifier,
              'mapped_control': subcategory,
              'relationship': 'REFERSTO'
            },
            properties={'mapping': 'csf'}))

    return stmts
FILE(REMOVE_RECURSE
  "CMakeFiles/generate-chromium-ansible-playbooks"
  "playbooks"
  "fixes/ansible"
)

# Per-language clean rules from dependency scanning.
FOREACH(lang)
  INCLUDE(CMakeFiles/generate-chromium-ansible-playbooks.dir/cmake_clean_${lang}.cmake OPTIONAL)
ENDFOREACH(lang)
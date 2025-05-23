---
title: Migrate KAS Grants

command:
  name: migrate
  aliases:
  - migrates
  description: Migrate Legacy KAS Grants to New Key Mappings
  flags:
  - name: commit
    description: Writes changes to policy storage
    default: false
  - name: interactive
    shorthand: i
    description: Interactive walk thru of migrations
    default: false
---

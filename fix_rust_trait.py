import re

with open('src/client.rs', 'r') as f:
    content = f.read()

# I will move the trait_def down. First I'll remove it from the top.
# trait_def starts with use async_trait::async_trait; and ends with `self.client.execute(req).await\n    }\n}\n\n`
# Actually it's easier to just git checkout src/client.rs and re-apply correctly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('Marketplace description fits the published character limit', () => {
  const metadata = readFileSync(new URL('../action.yml', import.meta.url), 'utf8');
  const description = /^description: (.+)$/m.exec(metadata)?.[1];
  assert.ok(description, 'a plain-text Action description is required');
  assert.ok([...description].length < 125, 'Marketplace descriptions must be less than 125 characters');
});

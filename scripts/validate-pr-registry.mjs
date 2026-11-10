import {readFile} from 'node:fs/promises';
import {parsePrRegistry} from '../registry/pr-contract.mjs';
const body = await readFile(new URL('../registry/prs.json', import.meta.url), 'utf8');
// The register is a historical record made under the repository's original owner. The repository has since moved to
// another organization under the same name. The record itself is validated strictly against its recorded identity;
// the checkout it is validated in must be that same repository (same name), under the recorded or the current owner.
const recorded = JSON.parse(body).repository;
const CURRENT_OWNER = 'Justice-For-All-Movement';
const current = process.env.GITHUB_REPOSITORY;
if (current) {
  const [owner, name, ...rest] = current.split('/');
  const [recordedOwner, recordedName] = String(recorded).split('/');
  if (rest.length > 0 || !name || name.toLowerCase() !== String(recordedName).toLowerCase() || ![recordedOwner, CURRENT_OWNER].includes(owner))
    throw new Error('PR registry belongs to a different repository.');
}
const {document} = parsePrRegistry(body, recorded);
for (const unit of document.units) for (const number of unit.prs) {
  if (!document.pullRequests.some(pr => pr.number === number)) throw new Error('Missing observed PR');
}
console.log(`Valid PR registry: ${document.repository}, ${document.units.length} approved units; live acceptance is separate.`);

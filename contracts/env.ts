import fs from 'fs';
import { parse } from 'dotenv';

export interface IEnvironment {
  OROCHI_MNEMONIC: string;
  OROCHI_RPC: string;
  OROCHI_FORK: boolean;
}

function clean(config: any): any {
  const entries = Object.entries(config);
  const cleaned: any = {};
  for (let i = 0; i < entries.length; i += 1) {
    const [k, v] = entries[i] as [string, string];
    if (k === 'OROCHI_FORK') {
      cleaned[k] = v.trim().toLowerCase() === 'true';
    } else {
      cleaned[k] = false;
    }
  }
  cleaned.OROCHI_FORK = cleaned.OROCHI_FORK || false;
  return cleaned;
}

export const env: IEnvironment = fs.existsSync(`${__dirname}/.env`)
  ? clean(parse(fs.readFileSync(`${__dirname}/.env`)) as any)
  : {
      OROCHI_FORK: false,
      OROCHI_MNEMONIC: 'baby nose young alone sport inside grain rather undo donor void exotic',
      OROCHI_RPC: 'http://localhost:8545',
    };

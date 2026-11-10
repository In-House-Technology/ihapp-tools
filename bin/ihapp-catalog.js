#!/usr/bin/env node
import { catalogMain } from '../src/ihapp-catalog-publish.js';

process.exitCode = catalogMain(process.argv.slice(2));

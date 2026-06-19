require('dotenv').config();
const ShodanClient = require('shodan-client');
const axios = require('axios');
const { IPINT } = require('../db');

// ANSI escape codes for colors and styles
const C = {
    Reset: "\x1b[0m",
    Bold: "\x1b[1m",
    Dim: "\x1b[2m",
    Red: "\x1b[31m",
    Green: "\x1b[32m",
    Yellow: "\x1b[33m",
    Cyan: "\x1b[36m",
    Magenta: "\x1b[35m",
    White: "\x1b[37m",
};

function safeParse(raw) {
    if (!raw) return {};
    try { return typeof raw === 'string' ? JSON.parse(raw) : raw; }
    catch(_) { return {}; }
}

async function fetchShodanData(ip, retries = 3) {
    try {
        const data = await ShodanClient.host(ip, process.env.SHODAN_API_KEY);
        console.log(`${C.Magenta}[5ELG-SHODAN]${C.Reset} Response for ${C.Bold}${ip}${C.Reset}: ${C.Dim}${JSON.stringify(data).slice(0, 200)}${C.Reset}`);
        return data;
    } catch (error) {
        console.error(`${C.Red}[5ELG-SHODAN] Error for ${ip}:${C.Reset}`, error.message);
        if (retries > 0) {
            console.warn(`${C.Yellow}[5ELG-SHODAN] Retrying in 5s... (${retries} left)${C.Reset}`);
            await new Promise(r => setTimeout(r, 5000));
            return fetchShodanData(ip, retries - 1);
        }
        return null;
    }
}

async function updateSHODANIPData(ip) {
    try {
        const [ipRecord] = await IPINT.findOrCreate({
            where: { IP: ip },
            defaults: { MAC: null, DATA: null, GEO: null, SCAN: false, INTEL: null },
        });

        const shodanData = await fetchShodanData(ip);
        if (!shodanData) {
            console.error(`${C.Red}[5ELG-SHODAN] No data for ${ip}${C.Reset}`);
            return;
        }

        const existingData = safeParse(ipRecord.DATA);
        const updatedData  = { ...existingData, shodan: shodanData };

        // DataTypes.JSON → objeto directo, sin JSON.stringify
        await ipRecord.update({ DATA: updatedData });
        console.log(`${C.Magenta}[5ELG-SHODAN]${C.Reset} Updated ${C.Bold}${ip}${C.Reset}`);
    } catch (error) {
        console.error(`${C.Red}[5ELG-SHODAN] updateSHODANIPData error:${C.Reset}`, error.message);
    }
}

async function fetchCriminalIPReport(ip) {
    const API_KEY = process.env.CRIMINALIP_API_KEY;
    if (!API_KEY) {
        console.error(`${C.Red}[5ELG-CRIMINALIP] CRIMINALIP_API_KEY not set${C.Reset}`);
        return null;
    }
    try {
        const { data } = await axios.get(
            `https://api.criminalip.io/v1/asset/ip/report?ip=${ip}&full=true`,
            { headers: { 'x-api-key': API_KEY } }
        );
        console.log(`${C.Magenta}[5ELG-CRIMINALIP]${C.Reset} Got data for ${C.Bold}${ip}${C.Reset}`);
        return data;
    } catch (error) {
        console.error(`${C.Red}[5ELG-CRIMINALIP] Error for ${ip}:${C.Reset}`, error.message);
        if (error.response) console.error(`${C.Dim}Details: ${JSON.stringify(error.response.data)}${C.Reset}`);
        return null;
    }
}

async function updateCriminalIPData(ip) {
    try {
        const [ipRecord] = await IPINT.findOrCreate({
            where: { IP: ip },
            defaults: { MAC: null, DATA: null, GEO: null, SCAN: false, INTEL: null },
        });

        const criminalIPData = await fetchCriminalIPReport(ip);
        if (!criminalIPData) {
            console.error(`${C.Red}[5ELG-CRIMINALIP] No data for ${ip}${C.Reset}`);
            return;
        }

        const existingData = safeParse(ipRecord.DATA);
        const updatedData  = { ...existingData, criminalip: criminalIPData };

        await ipRecord.update({ DATA: updatedData });
        console.log(`${C.Magenta}[5ELG-CRIMINALIP]${C.Reset} Updated ${C.Bold}${ip}${C.Reset}`);
    } catch (error) {
        console.error(`${C.Red}[5ELG-CRIMINALIP] updateCriminalIPData error:${C.Reset}`, error.message);
    }
}

module.exports = { updateSHODANIPData, updateCriminalIPData };
const { DataTypes } = require('sequelize');
const { Sequelize } = require('sequelize');
const { Op } = require('sequelize');

require('dotenv').config();


// Crear la instancia de Sequelize apuntando a la base de datos SQLite
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: process.env.DB_PATH,
    logging: false,
    dialectOptions: {
        // Wait up to 5 s before giving up on a locked DB instead of throwing immediately
        busyTimeout: 5000,
    },
    pool: { max: 1, min: 0, acquire: 30000, idle: 10000 },
});


const Log = sequelize.define('Log', {
    ID: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    Ts: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    Dl: DataTypes.STRING,
    Ed: DataTypes.STRING,
    Er: DataTypes.STRING,
    html: DataTypes.BLOB,
    screen: DataTypes.BLOB,
    Ip: DataTypes.STRING,
    Ua: DataTypes.STRING,
    Fu: DataTypes.STRING,
    Fb: DataTypes.STRING,
    Fr: DataTypes.STRING,
    Jd: DataTypes.STRING,
}, {
    tableName: 'logs',
    timestamps: false
});


// Modelo IPINT
const IPINT = sequelize.define('IPINT', {
    ID: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    IP: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    MAC: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    DATA: {
        type: DataTypes.JSON, // Puede almacenar información adicional en texto
        allowNull: true,
    },
    GEO: {
        type: DataTypes.JSON, // Datos geográficos como JSON (país, ciudad, latitud, longitud, etc.)
        allowNull: true,
    },
    SCAN: {
        type: DataTypes.BOOLEAN, // Indica si se ha escaneado la IP
        allowNull: true,
        defaultValue: false,
    },
    INTEL: {
        type: DataTypes.TEXT, // Información adicional relacionada con inteligencia (puede ser texto o JSON)
        allowNull: true,
    },
}, {
    tableName: 'ipint',
    timestamps: false
});

const FINGERDATA = sequelize.define('fingerprinted', {
    ID: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    FU: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    FB: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    IPS: {
        type: DataTypes.JSON, // Puede almacenar información adicional en texto
        allowNull: true,
    },
    NETDATA: {
        type: DataTypes.JSON, // Puede almacenar información adicional en texto
        allowNull: true,
    },
    INTEL: {
        type: DataTypes.JSON, // Puede almacenar información adicional en texto
        allowNull: true,
    },
    PWD: {
        type: DataTypes.JSON, // Puede almacenar información adicional en texto
        allowNull: true,
    }
}, {
    tableName: 'fingerprinted',
    timestamps: false
});

/**
 * 
 * 
 
 * 
 * 
// Modelo PROXY_REQ
const PROXY_REQ = sequelize.define('IPINT', {
    ID: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    IP: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    REQUEST: {
        type: DataTypes.JSON, // Puede almacenar información adicional en texto
        allowNull: true,
    },
    RESPONSE: {
        type: DataTypes.JSON, // Datos geográficos como JSON (país, ciudad, latitud, longitud, etc.)
        allowNull: true,
    },
    DATA: {
        type: DataTypes.BOOLEAN, // Indica si se ha escaneado la IP
        allowNull: true,
        defaultValue: false,
    },
    INYECT: {
        type: DataTypes.TEXT, // Información adicional relacionada con inteligencia (puede ser texto o JSON)
        allowNull: true,
    },
}, {
    tableName: 'proxy',
    timestamps: false
});

const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:');

// Modelo MAIL_SERVER
const MAIL_SERVER = sequelize.define('mail_server', {
    ID: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    MAILFROM: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    NAILTO: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    MAILSUBJECT: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    MAILBODY: {
        type: DataTypes.TEXT,
        allowNull: true,
    },
    ATTACHMENTS: {
        type: DataTypes.JSON,
        allowNull: true,
    },
    RECEIVED_AT: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW,
    }
}, {
    tableName: 'mail_server',
    timestamps: false
});

module.exports = { MAIL_SERVER };


 */

// Enable WAL mode once on startup — reduces SQLITE_BUSY under concurrent writes
sequelize.query('PRAGMA journal_mode=WAL;').catch(() => {});
sequelize.query('PRAGMA synchronous=NORMAL;').catch(() => {});

module.exports = {
    Op,
    sequelize,
    FINGERDATA,
    Log, 
    IPINT
};
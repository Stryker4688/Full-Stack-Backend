// backend/src/config/logger.ts
import winston from 'winston';
import 'winston-daily-rotate-file';
import path from 'path';

// ایجاد پوشه logs اگر وجود ندارد
const logsDir = path.join(__dirname, '../../logs');
import fs from 'fs';
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// تعریف فرمت لاگ‌ها
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
        let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;

        if (stack) {
            log += `\n${stack}`;
        }

        if (Object.keys(meta).length > 0) {
            log += `\n${JSON.stringify(meta, null, 2)}`;
        }

        return log;
    })
);

// ایجاد transports مختلف
const transports = {
    console: new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            logFormat
        ),
        level: process.env.NODE_ENV === 'production' ? 'info' : 'debug'
    }),

    file: new winston.transports.DailyRotateFile({
        filename: path.join(logsDir, 'application-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
        format: logFormat,
        level: 'info'
    }),

    errorFile: new winston.transports.DailyRotateFile({
        filename: path.join(logsDir, 'error-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
        format: logFormat,
        level: 'error'
    }),

    httpFile: new winston.transports.DailyRotateFile({
        filename: path.join(logsDir, 'http-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
        format: logFormat,
        level: 'http'
    })
};

// ایجاد logger instance
export const logger = winston.createLogger({
    levels: {
        error: 0,
        warn: 1,
        info: 2,
        debug: 3,
        http: 4
    },
    format: logFormat,
    defaultMeta: { service: 'fullstack-backend' },
    transports: [
        transports.console,
        transports.file,
        transports.errorFile,
        transports.httpFile
    ],
    exceptionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'exceptions.log')
        })
    ],
    rejectionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'rejections.log')
        })
    ]
});

// اگر در حالت development هستیم، لاگ‌های debug رو هم به فایل اضافه کن
if (process.env.NODE_ENV === 'development') {
    logger.add(new winston.transports.File({
        filename: path.join(logsDir, 'debug.log'),
        level: 'debug',
        format: logFormat
    }));
}

export default logger;
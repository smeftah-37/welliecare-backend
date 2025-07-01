import { Justificatif } from "src/entities/justificatif.entity";
import { Professional } from "src/entities/professional.entity";
import { User } from "src/entities/user.entity";
import { DataSourceOptions } from "typeorm";
import * as dotenv from 'dotenv';

dotenv.config();

export const datasourceoptions : DataSourceOptions ={
    type:'postgres',
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || "5432", 10),
    username: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    database: process.env.POSTGRES_DB,
    entities: [User
, Justificatif,Professional
    ],
    synchronize: true,
    // migrations:['dist/migrations/*.js'],
    extra: {
        max: 100, 
        min: 5,  
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000, 
      },

    
}
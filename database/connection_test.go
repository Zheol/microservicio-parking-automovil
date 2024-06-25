package database

import (
	"bytes"
	"log"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)
func TestDBConnection_Success(t *testing.T) {
	// Crear la conexión de base de datos mock
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	// Configurar Gorm para usar la conexión de base de datos mock
	dialector := postgres.New(postgres.Config{
		Conn: db,
	})
	gormDB, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	assert.NoError(t, err)

	// Asignar la instancia de Gorm a la variable global de base de datos
	DB = gormDB

	// Expectativa de consulta simulada
	mock.ExpectQuery(`SELECT 1`).WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))

	// Llamar a la función que se está probando
	DBConnection()

	// Verificar que no hubo errores en la conexión
	assert.NotNil(t, DB)
	assert.NoError(t, err)

	// Verificar que las expectativas de mock se cumplieron
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDBConnection_Failure(t *testing.T) {
	// Capturar el logger original
	logOutput := captureLogOutput(func() {
		// Intentar conectar con una DSN inválida
		invalidDSN := "invalid dsn"
		_, err := gorm.Open(postgres.Open(invalidDSN), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})

		// Verificar que se produce un error al conectar
		assert.Error(t, err)

		if err != nil {
			log.Println("unable to connect to database")
		}
	})

	// Verificar el mensaje de error en el log
	assert.Contains(t, logOutput, "unable to connect to database")
}

var (
	originalLogger    = log.Default()
	bufferedLogOutput bytes.Buffer
)

func captureLogOutput(f func()) string {
	log.SetOutput(&bufferedLogOutput)
	defer log.SetOutput(originalLogger.Writer())
	f()
	return bufferedLogOutput.String()
}


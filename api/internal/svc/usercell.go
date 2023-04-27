package svc

import "time"

type CellEntry struct {
	timeStart  time.Time
	prisonTerm time.Time
	flag       byte
}

func NewCellEntry() *CellEntry {
	timeNow := time.Now()
	return &CellEntry{
		timeStart:  timeNow,
		prisonTerm: timeNow,
		flag:       byte(0x01),
	}
}

func (svcCtx *ServiceContext) CellCalled(username string, passed bool) {
	timeNow := time.Now()
	if passed {
		// Login succeed, delete cell entry
		delete(svcCtx.UserCell, username)
		return
	}

	cell, ok := svcCtx.UserCell[username]
	if !ok {
		// The first time login failed, create a new cell entry
		svcCtx.UserCell[username] = NewCellEntry()
		return
	}

	if timeNow.After(cell.timeStart.Add(30 * time.Second)) {
		// 30 seconds passwd after the first failed, initial entry
		cell.timeStart = timeNow
		cell.prisonTerm = timeNow
		cell.flag = byte(0x01)
		return
	}

	// Failed time count
	cell.flag = cell.flag << 1

	// Set prison term
	if cell.flag == 0x10 {
		cell.prisonTerm = timeNow.Add(10 * time.Second)
	}
}

func (svcCtx *ServiceContext) CellCheck(username string) bool {
	if cellEntry, ok := svcCtx.UserCell[username]; ok {
		if cellEntry.prisonTerm.After(time.Now()) {
			return false
		}
	}

	return true
}

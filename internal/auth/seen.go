package auth

import "sync"

// Seen помнит, кого уже видели с момента запуска.
//
// Нужен, чтобы событие «человек авторизовался» попадало в журнал один
// раз, а не на каждый его запрос. Собственного события входа у шлюза нет —
// вход делает auth-service, — поэтому за него принимается первая встреча с
// готовой кукой.
//
// Память не растёт бесконечно: резидентов десятки, а не миллионы, и набор
// очищается при перезапуске вместе с процессом.
type Seen struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

// NewSeen создаёт пустой набор.
func NewSeen() *Seen { return &Seen{ids: make(map[string]struct{})} }

// First сообщает, встречается ли идентификатор впервые, и запоминает его.
func (s *Seen) First(id string) bool {
	if s == nil || id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[id]; ok {
		return false
	}
	s.ids[id] = struct{}{}
	return true
}

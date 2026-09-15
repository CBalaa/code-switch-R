package services

import "sync"

// EventEmitter publishes named events to interested subscribers.
type EventEmitter interface {
	Emit(name string, payload any)
}

// UserScopedEvent 事件载荷可实现该接口，声明事件归属的用户。
// SSE 层据此只把事件投递给该用户；返回空字符串表示广播。
type UserScopedEvent interface {
	EventUserID() string
}

// EventMessage is the normalized payload sent over the in-process event bus.
type EventMessage struct {
	Name string
	Data any
}

// EventHub is a small fan-out event bus used by the web runtime and SSE layer.
type EventHub struct {
	mu          sync.RWMutex
	nextID      int
	subscribers map[int]chan EventMessage
}

func NewEventHub() *EventHub {
	return &EventHub{
		subscribers: make(map[int]chan EventMessage),
	}
}

func (h *EventHub) Emit(name string, payload any) {
	h.mu.RLock()
	subscribers := make([]chan EventMessage, 0, len(h.subscribers))
	for _, ch := range h.subscribers {
		subscribers = append(subscribers, ch)
	}
	h.mu.RUnlock()

	msg := EventMessage{Name: name, Data: payload}
	for _, ch := range subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *EventHub) Subscribe(buffer int) (<-chan EventMessage, func()) {
	if buffer <= 0 {
		buffer = 16
	}

	ch := make(chan EventMessage, buffer)

	h.mu.Lock()
	id := h.nextID
	h.nextID++
	h.subscribers[id] = ch
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		if _, ok := h.subscribers[id]; ok {
			delete(h.subscribers, id)
		}
		h.mu.Unlock()
	}

	return ch, cancel
}

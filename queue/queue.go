package queue

import (
	"unsafe"
	"sync/atomic"
	"runtime"
)

// lock free queue
type Queue struct {
	head  unsafe.Pointer
	tail  unsafe.Pointer
	Reset func(interface{})
	New func() interface{}
}

// one node in queue
type Node struct {
	val  interface{}
	next unsafe.Pointer
}

func QueueNew()(*Queue){
	queue := new(Queue)
	queue.head =  unsafe.Pointer(new(Node))
	queue.tail = queue.head
	return queue
}



// queue functions
func (self *Queue) EnQueue(val interface{}) {

	if self.Reset!= nil{
		self.Reset(val)
	}
	newNode := unsafe.Pointer(&Node{val: val, next: nil})
	var tail, next unsafe.Pointer
	for {
		tail = self.tail
		next = ((*Node)(tail)).next
		if tail != self.tail{
			runtime.Gosched()
			continue
		}
		if next != nil {
			atomic.CompareAndSwapPointer(&(self.tail), tail, next)
			continue
		}
		if atomic.CompareAndSwapPointer(&((*Node)(tail).next), nil,newNode ) {
		    break
		}
		runtime.Gosched()
	}
	atomic.CompareAndSwapPointer(&(self.tail),tail, newNode)
}

func (self *Queue) DeQueue() (val interface{}) {
	var head, tail, next unsafe.Pointer
	for {
		head = self.head
		tail = self.tail
		next = ((*Node)(head)).next
		if head != self.head{
			runtime.Gosched()
			continue
		}
		if next == nil{
			if self.New != nil{
				return self.New()
			}else{
				return nil
			}

		}
		if head == tail {
			atomic.CompareAndSwapPointer(&(self.tail), tail, next)
		}else{
			val = ((*Node)(next)).val
			if atomic.CompareAndSwapPointer(&(self.head), head, next) {
				return val
		    	}
		}
		runtime.Gosched()
	}
}
